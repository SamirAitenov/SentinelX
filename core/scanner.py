import os

from core.heuristic_engine import heuristic_analysis
from core.hash_checker import is_malicious_hash
from core.quarantine import move_to_quarantine
from core.logger import log_event
from core.database import save_threat
from core.behavior_monitor import analyze as behavior_analyze


def scan_file(file_path):
    threats = []

    if is_malicious_hash(file_path):
        threats.append("Malicious hash detected")

    risk = heuristic_analysis(file_path)

    if risk == "HIGH":
        threats.append("High heuristic score")

    # behavioral analysis — always runs, adds detail even for MEDIUM files
    behavior = behavior_analyze(file_path)

    if behavior["verdict"] == "MALICIOUS" and "Behavioral analysis" not in threats:
        threats.append(f"Behavioral analysis: {behavior['total_indicators']} indicators")

    if threats:
        move_to_quarantine(file_path)
        log_event(f"Threat detected: {file_path}")
        log_event(f"Behavioral score: {behavior['score']}/100 — {behavior['verdict']}")
        save_threat(file_path, risk)
        return {
            "file":     file_path,
            "risk":     risk,
            "threats":  threats,
            "behavior": behavior,
        }

    # even if not quarantined — return behavior data if suspicious
    if behavior["verdict"] == "SUSPICIOUS":
        log_event(f"Suspicious behavior detected in: {os.path.basename(file_path)}")
        return {
            "file":     file_path,
            "risk":     risk,
            "threats":  [f"Suspicious behavior: {behavior['total_indicators']} indicators"],
            "behavior": behavior,
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
