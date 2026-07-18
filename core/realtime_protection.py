from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from core.scanner import scan_file
from core.logger import log_event

import os
import time
import threading

# SentinelX's own working folders/files — never scan these
IGNORED_PATH_PARTS = (
    os.sep + "quarantine" + os.sep,
    os.sep + "logs" + os.sep,
)
IGNORED_FILENAMES = {"sentinelx.db", "sentinelx.db-journal", "events.log"}

# How long to wait after a file event before scanning it.
# Gives the OS time to finish writing the file to disk.
SCAN_DELAY_SECONDS = 1.5


def _should_ignore(path):
    normalized = os.path.abspath(path) + os.sep

    for part in IGNORED_PATH_PARTS:
        if part in normalized:
            return True

    return os.path.basename(path) in IGNORED_FILENAMES


class RealtimeHandler(FileSystemEventHandler):

    def __init__(self):
        super().__init__()
        # tracks files we already scheduled a scan for, to avoid double-scanning
        # the same file when both on_created and on_modified fire together
        self._pending = set()
        self._lock = threading.Lock()

    def _schedule_scan(self, path):
        abs_path = os.path.abspath(path)

        with self._lock:
            if abs_path in self._pending:
                return  # already scheduled, skip duplicate event
            self._pending.add(abs_path)

        def _do_scan():
            time.sleep(SCAN_DELAY_SECONDS)  # wait for file to finish writing

            with self._lock:
                self._pending.discard(abs_path)

            if not os.path.exists(abs_path):
                return  # file was deleted in the meantime

            log_event(f"New file detected: {abs_path}")
            scan_file(abs_path)

        thread = threading.Thread(target=_do_scan, daemon=True)
        thread.start()

    def on_created(self, event):
        if event.is_directory:
            return
        if _should_ignore(event.src_path):
            return
        self._schedule_scan(event.src_path)

    def on_modified(self, event):
        # Catches the case where a file is created empty then written to
        if event.is_directory:
            return
        if _should_ignore(event.src_path):
            return
        self._schedule_scan(event.src_path)


def start_realtime_protection(path):

    event_handler = RealtimeHandler()

    observer = Observer()

    observer.schedule(
        event_handler,
        path,
        recursive=True
    )

    observer.start()

    log_event("Realtime protection enabled")

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        observer.stop()

    observer.join()
