"""
Feature extraction for the ML model.

Every file is converted into a fixed-length numeric vector.
The model never sees raw bytes or text — only these numbers.
That makes it fast, language-agnostic, and hard to fool by renaming.
"""

import os
import re
import math
import string

# ---------------------------------------------------------------------------
# Feature list (order matters — must be identical at train + predict time)
# ---------------------------------------------------------------------------
FEATURE_NAMES = [
    "file_size_kb",          # raw size in KB
    "entropy",               # Shannon entropy of file content (0–8)
    "suspicious_ext",        # 1 if extension is .bat .exe .vbs .ps1 .scr .dll, else 0
    "keyword_count",         # total hits of suspicious keywords
    "unique_keywords",       # how many distinct suspicious keywords appear
    "url_count",             # number of http:// or https:// occurrences
    "ip_count",              # number of IP address patterns (x.x.x.x)
    "base64_score",          # rough likelihood of base64 blobs (long alphanum runs)
    "line_count",            # total number of lines
    "avg_line_length",       # average characters per line
    "uppercase_ratio",       # fraction of uppercase letters (0–1)
    "digit_ratio",           # fraction of digit characters (0–1)
    "special_char_ratio",    # fraction of non-alphanumeric, non-space chars (0–1)
    "non_ascii_ratio",       # fraction of bytes outside printable ASCII
    "unique_line_ratio",     # unique lines / total lines (low = repetitive = packer)
]

SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".vbs", ".ps1", ".scr", ".dll", ".cmd", ".pif"}

SUSPICIOUS_KEYWORDS = [
    "powershell", "cmd.exe", "reg add", "reg delete", "taskkill",
    "wget", "curl", "net user", "net localgroup", "schtasks",
    "wscript", "cscript", "mshta", "rundll32", "regsvr32",
    "certutil", "bitsadmin", "invoke-expression", "iex(",
    "hidden", "bypass", "-enc", "frombase64", "shellcode",
    "createobject", "shell.application", "winmgmts",
    "disable", "firewall", "netsh", "attrib +h", "icacls",
]


def _shannon_entropy(data: bytes) -> float:
    """Measures randomness. High entropy (>7) suggests encryption/packing."""
    if not data:
        return 0.0

    freq = [0] * 256
    for byte in data:
        freq[byte] += 1

    entropy = 0.0
    length = len(data)
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)

    return round(entropy, 4)


def _count_base64(text: str) -> float:
    """
    Returns a 0–1 score based on presence of long base64-like strings.
    Real base64 blobs are a strong indicator of obfuscation.
    """
    # Look for runs of base64 alphabet chars >= 40 chars long
    pattern = r"[A-Za-z0-9+/]{40,}={0,2}"
    matches = re.findall(pattern, text)
    if not matches:
        return 0.0
    # Normalise: cap at 5 matches → score 1.0
    return min(len(matches) / 5.0, 1.0)


def extract_features(file_path: str) -> list[float] | None:
    """
    Returns a list of floats (one per FEATURE_NAMES entry), or None if the
    file cannot be read (locked, missing, binary-only, etc.).
    """
    try:
        stat = os.stat(file_path)
        file_size_kb = stat.st_size / 1024.0

        with open(file_path, "rb") as f:
            raw = f.read()

    except Exception:
        return None

    # ---- decode as text (ignore bad bytes) --------------------------------
    text = raw.decode("utf-8", errors="ignore").lower()
    lines = text.splitlines() if text else []

    # ---- entropy -----------------------------------------------------------
    entropy = _shannon_entropy(raw)

    # ---- extension ---------------------------------------------------------
    ext = os.path.splitext(file_path)[1].lower()
    suspicious_ext = 1.0 if ext in SUSPICIOUS_EXTENSIONS else 0.0

    # ---- keywords ----------------------------------------------------------
    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text]
    keyword_count = float(len(keyword_hits))
    unique_keywords = float(len(set(keyword_hits)))

    # ---- urls & ips --------------------------------------------------------
    url_count = float(len(re.findall(r"https?://", text)))
    ip_count  = float(len(re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text
    )))

    # ---- base64 ------------------------------------------------------------
    base64_score = _count_base64(text)

    # ---- line stats --------------------------------------------------------
    line_count = float(len(lines)) if lines else 1.0
    avg_line_length = (
        sum(len(l) for l in lines) / line_count if lines else 0.0
    )
    unique_line_ratio = (
        len(set(lines)) / line_count if lines else 1.0
    )

    # ---- character ratios (use original-case text for accuracy) ------------
    text_orig = raw.decode("utf-8", errors="ignore")
    total_chars = len(text_orig) if text_orig else 1

    uppercase_ratio = sum(1 for c in text_orig if c.isupper()) / total_chars
    digit_ratio     = sum(1 for c in text_orig if c.isdigit()) / total_chars
    printable       = set(string.printable)
    special_char_ratio = sum(
        1 for c in text_orig if c not in printable or (
            not c.isalnum() and c not in string.whitespace
        )
    ) / total_chars
    non_ascii_ratio = sum(1 for b in raw if b > 127) / len(raw) if raw else 0.0

    return [
        file_size_kb,
        entropy,
        suspicious_ext,
        keyword_count,
        unique_keywords,
        url_count,
        ip_count,
        base64_score,
        line_count,
        avg_line_length,
        uppercase_ratio,
        digit_ratio,
        special_char_ratio,
        non_ascii_ratio,
        unique_line_ratio,
    ]
