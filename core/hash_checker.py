import hashlib

MALICIOUS_HASHES = {
    "5d41402abc4b2a76b9719d911017c592"
}

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