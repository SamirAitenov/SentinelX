import hashlib
import os

HASH_DB_PATH = os.path.join(os.path.dirname(__file__), "malware_hashes.txt")


def load_hashes(path=HASH_DB_PATH):
    hashes = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#")[0].strip().lower()
                if len(line) == 64:
                    hashes.add(line)
    except FileNotFoundError:
        pass
    return hashes


MALICIOUS_HASHES = load_hashes()


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while chunk := file.read(4096):
                sha256.update(chunk)

        return sha256.hexdigest()

    except:
        return None


def is_malicious_hash(file_path):
    file_hash = calculate_sha256(file_path)

    if file_hash in MALICIOUS_HASHES:
        return True

    return False
