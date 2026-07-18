from datetime import datetime
import os

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "events.log")

os.makedirs(LOG_DIR, exist_ok=True)

def log_event(message):
    time = datetime.now().strftime("%H:%M:%S")
    
    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(f"[{time}] {message}\n")


def read_events(limit=200):
    """Returns the most recent log lines, newest first."""
    if not os.path.exists(LOG_FILE):
        return []

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            lines = [line.rstrip("\n") for line in file if line.strip()]
    except Exception:
        return []

    return list(reversed(lines[-limit:]))


def clear_events():
    try:
        open(LOG_FILE, "w", encoding="utf-8").close()
        log_event("Log cleared by user")
        return True
    except Exception:
        return False