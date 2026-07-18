import os

SUSPICIOUS_EXTENSIONS = [
    ".exe",
    ".bat",
    ".vbs",
    ".ps1",
    ".scr"
]

SUSPICIOUS_KEYWORDS = [
    "powershell",
    "cmd.exe",
    "reg add",
    "taskkill",
    "wget",
    "curl"
]


def heuristic_analysis(file_path):
    score = 0

    extension = os.path.splitext(file_path)[1].lower()

    if extension in SUSPICIOUS_EXTENSIONS:
        score += 30

    try:
        with open(file_path, "r", errors="ignore") as file:
            content = file.read().lower()

            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in content:
                    score += 20

    except:
        pass

    if score >= 60:
        return "HIGH"

    elif score >= 30:
        return "MEDIUM"

    return "LOW"