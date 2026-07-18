import shutil
import os
from datetime import datetime
from core.logger import log_event

QUARANTINE_FOLDER = "quarantine"
ORIGIN_FOLDER = "quarantine_origin"  # remembers where a file came from, for Restore

os.makedirs(QUARANTINE_FOLDER, exist_ok=True)


def move_to_quarantine(file_path):
    try:
        filename = os.path.basename(file_path)

        destination = os.path.join(
            QUARANTINE_FOLDER,
            filename
        )

        # avoid clobbering an existing quarantined file with the same name
        if os.path.exists(destination):
            stamp = datetime.now().strftime("%H%M%S")
            name, ext = os.path.splitext(filename)
            destination = os.path.join(
                QUARANTINE_FOLDER,
                f"{name}_{stamp}{ext}"
            )

        shutil.move(file_path, destination)
        _remember_origin(os.path.basename(destination), file_path)

        log_event(f"File moved to quarantine: {filename}")

        return True

    except Exception as e:
        log_event(f"Quarantine error: {e}")
        return False


def list_quarantine_files():
    """Returns [{name, path, size, date}] for every file currently in quarantine."""
    items = []

    if not os.path.isdir(QUARANTINE_FOLDER):
        return items

    for name in os.listdir(QUARANTINE_FOLDER):
        if name.startswith("."):
            continue  # skip internal bookkeeping files like .origins

        full_path = os.path.join(QUARANTINE_FOLDER, name)

        if os.path.isfile(full_path):
            stat = os.stat(full_path)
            items.append({
                "name": name,
                "path": full_path,
                "size": stat.st_size,
                "date": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            })

    items.sort(key=lambda item: item["date"], reverse=True)
    return items


def restore_from_quarantine(filename, target_dir=None):
    """Moves a quarantined file back to its original folder (or target_dir if given)."""
    try:
        source = os.path.join(QUARANTINE_FOLDER, filename)

        if not os.path.exists(source):
            return False

        if target_dir is None:
            target_dir = _recall_origin(filename) or "."

        os.makedirs(target_dir, exist_ok=True)
        destination = os.path.join(target_dir, filename)

        shutil.move(source, destination)
        _forget_origin(filename)

        log_event(f"File restored from quarantine: {filename}")
        return True

    except Exception as e:
        log_event(f"Restore error: {e}")
        return False


def delete_from_quarantine(filename):
    """Permanently deletes a quarantined file."""
    try:
        target = os.path.join(QUARANTINE_FOLDER, filename)

        if not os.path.exists(target):
            return False

        os.remove(target)
        _forget_origin(filename)

        log_event(f"File permanently deleted: {filename}")
        return True

    except Exception as e:
        log_event(f"Delete error: {e}")
        return False


def _origin_map_path():
    return os.path.join(QUARANTINE_FOLDER, ".origins")


def _remember_origin(filename, original_path):
    try:
        origin_dir = os.path.dirname(original_path) or "."
        with open(_origin_map_path(), "a", encoding="utf-8") as f:
            f.write(f"{filename}\t{origin_dir}\n")
    except Exception:
        pass


def _recall_origin(filename):
    path = _origin_map_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                name, _, origin = line.strip().partition("\t")
                if name == filename:
                    return origin
    except Exception:
        pass
    return None


def _forget_origin(filename):
    path = _origin_map_path()
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [line for line in f if not line.startswith(filename + "\t")]
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except Exception:
        pass