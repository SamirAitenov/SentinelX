import os

from core.heuristic_engine import heuristic_analysis
from core.hash_checker import is_malicious_hash
from core.quarantine import move_to_quarantine
from core.logger import log_event
from core.database import save_threat


def scan_file(file_path):
    threats = []

    if is_malicious_hash(file_path):
        threats.append("Malicious hash detected")
    risk = heuristic_analysis(file_path)
    
    if risk == "HIGH":
        threats.append("High heuristic score")

    if threats:
        move_to_quarantine(file_path)
        log_event(f"Threat detected: {file_path}")
        save_threat(file_path, risk)
        return {
            "file": file_path,
            "risk": risk,
            "threats": threats
        }
    return None


def scan_directory(directory):
    results = []

    for root, dirs, files in os.walk(directory):
        for file in files:

            file_path = os.path.join(root, file)

            result = scan_file(file_path)

            if result:
                results.append(result)

    return results