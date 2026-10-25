import os
import re

INDICATORS = {
    "persistence": [
        (r"hkcu\\software\\microsoft\\windows\\currentversion\\run",
         "Write to HKCU Run key — file executes on user login",
         3),
        (r"hklm\\software\\microsoft\\windows\\currentversion\\run",
         "Write to HKLM Run key — file executes on every boot",
         3),
        (r"hklm\\system\\currentcontrolset\\services",
         "Modifies Windows Services registry — can install as service",
         3),
        (r"schtasks\s+/create",
         "Creates a scheduled task — persists via Task Scheduler",
         3),
        (r"startup",
         "References Startup folder — drops file for autorun",
         2),
        (r"winlogon",
         "References Winlogon — can hijack login process",
         2),
        (r"userinit",
         "Modifies Userinit — executes on every login",
         2),
        (r"reg\s+add.*\\run",
         "Adds registry Run entry",
         3),
        (r"set-itemproperty.*run",
         "PowerShell registry persistence via Set-ItemProperty",
         3),
        (r"new-service",
         "Creates a new Windows service",
         2),
    ],

    "network": [
        (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
         "Connects directly to IP address (bypasses DNS — C2 indicator)",
         3),
        (r"https?://[a-z0-9\-]+\.(xyz|tk|ml|ga|cf|top|ru|cn|pw)",
         "Connects to high-risk TLD domain",
         3),
        (r"wget\s+http",
         "Downloads file via wget",
         2),
        (r"curl\s+-[oO]",
         "Downloads file via curl",
         2),
        (r"downloadstring|downloadfile|webclient",
         "Uses .NET WebClient to download content",
         3),
        (r"invoke-webrequest|iwr\s",
         "Uses PowerShell Invoke-WebRequest",
         2),
        (r"bitsadmin\s+/transfer",
         "Uses BITS service to download — evades firewall",
         3),
        (r"certutil.*-decode|certutil.*-urlcache",
         "Abuses certutil for download (LOLBin technique)",
         3),
        (r"new-object\s+net\.webclient",
         "Creates .NET WebClient object",
         2),
        (r"socket|connect\(|bind\(",
         "Raw socket connection — possible backdoor",
         2),
        (r"dns\.|nslookup|resolve-dnsname",
         "DNS lookup — possible domain-based C2",
         1),
    ],

    "evasion": [
        (r"taskkill.*\/im.*(antivirus|defender|avast|avg|kaspersky|norton|mcafee|malware)",
         "Attempts to kill antivirus process",
         3),
        (r"netsh.*firewall.*disable|netsh.*advfirewall.*off",
         "Disables Windows Firewall",
         3),
        (r"set-mppreference.*disablerealtimemonitoring",
         "Disables Windows Defender real-time monitoring",
         3),
        (r"-windowstyle\s+hidden|-w\s+hidden",
         "Runs process in hidden window — user cannot see it",
         2),
        (r"-executionpolicy\s+bypass",
         "Bypasses PowerShell execution policy",
         2),
        (r"attrib\s+\+h|\+s|\+r",
         "Sets file as hidden/system/read-only",
         2),
        (r"frombase64string|::frombase64|base64",
         "Base64 decoding — likely obfuscating payload",
         2),
        (r"invoke-expression|iex\(",
         "Executes dynamic string as code (obfuscation technique)",
         3),
        (r"reflection\.assembly|loadwithpartialname",
         "Loads .NET assembly at runtime — possible injection",
         2),
        (r"amsiutils|amsiscanstring",
         "References AMSI — possible attempt to bypass antimalware",
         3),
        (r"wscript\.sleep|start-sleep",
         "Time delay — evades sandbox timeout",
         1),
        (r"virtualalloc|writeprocessmemory|createremotethread",
         "Memory manipulation API — possible shellcode injection",
         3),
    ],

    "destruction": [
        (r"del\s+\/[fsq]|remove-item.*-recurse",
         "Recursive file deletion",
         3),
        (r"format\s+[a-z]:|diskpart",
         "Disk formatting — destroys all data",
         3),
        (r"vssadmin\s+delete\s+shadows",
         "Deletes Volume Shadow Copies — ransomware indicator",
         3),
        (r"bcdedit.*recoveryenabled\s+no",
         "Disables Windows recovery — ransomware indicator",
         3),
        (r"wbadmin\s+delete",
         "Deletes Windows backups",
         3),
        (r"rd\s+\/s\s+\/q",
         "Silent recursive directory removal",
         2),
        (r"encrypt|cipher\s+\/e",
         "File encryption activity",
         2),
        (r"get-childitem.*encrypt|foreach.*encrypt",
         "Iterates files for encryption — ransomware pattern",
         3),
        (r"overwrite|shred|wipe",
         "Secure file overwriting — anti-forensics",
         2),
    ],
    
    "privilege": [
        (r"net\s+localgroup\s+administrators.*\/add",
         "Adds user to local Administrators group",
         3),
        (r"net\s+user.*\/add",
         "Creates a new user account",
         2),
        (r"runas\s+\/user:administrator",
         "Attempts to run as Administrator",
         2),
        (r"whoami\s+\/priv",
         "Enumerates current privileges",
         1),
        (r"seimpersonateprivilege|sedebugprivilege",
         "References dangerous privileges — token impersonation",
         3),
        (r"bypass.*uac|uac.*bypass",
         "UAC bypass attempt",
         3),
        (r"eventvwr|fodhelper|computerdefaults",
         "Known UAC bypass binary referenced",
         3),
        (r"icacls.*\/grant.*:f",
         "Grants full permissions to file/folder",
         2),
    ],

    "lateral": [
        (r"net\s+use\s+\\\\",
         "Maps network share — lateral movement indicator",
         2),
        (r"psexec|paexec",
         "Remote execution tool — lateral movement",
         3),
        (r"wmic.*/node:",
         "Remote WMIC command execution",
         2),
        (r"enter-pssession|new-pssession|invoke-command.*computername",
         "PowerShell remoting to other machine",
         2),
        (r"copy.*\\\\.*\\[a-z]\$",
         "Copies file to admin share (C$, D$, ADMIN$)",
         3),
        (r"at\s+\\\\",
         "Schedules remote task on other machine",
         2),
        (r"mimikatz|sekurlsa|lsadump",
         "Credential dumping tool referenced",
         3),
        (r"hashdump|ntlm|pass-the-hash",
         "Hash-based authentication attack",
         3),
    ],
}

CATEGORY_NAMES = {
    "persistence": "Persistence",
    "network":     "Network Activity",
    "evasion":     "Defense Evasion",
    "destruction": "Data Destruction",
    "privilege":   "Privilege Escalation",
    "lateral":     "Lateral Movement",
}

SEVERITY_NAMES = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}
SEVERITY_SCORE = {1: 5, 2: 15, 3: 30}

def analyze(file_path: str) -> dict:
    result = {
        "file":             file_path,
        "readable":         False,
        "categories":       {cat: [] for cat in INDICATORS},
        "total_indicators": 0,
        "score":            0,
        "verdict":          "CLEAN",
        "summary":          [],
    }
    
    try:
        with open(file_path, "r", errors="ignore", encoding="utf-8") as f:
            content = f.read().lower()
        result["readable"] = True
    except Exception as e:
        result["summary"].append(f"Could not read file: {e}")
        return result

    if not content.strip():
        result["summary"].append("File is empty — nothing to analyse.")
        return result

    total_score = 0
    for category, patterns in INDICATORS.items():
        for pattern, description, severity in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                finding = {
                    "description": description,
                    "severity":    SEVERITY_NAMES[severity],
                    "severity_int": severity,
                    "pattern":     pattern,
                }
                result["categories"][category].append(finding)
                total_score += SEVERITY_SCORE[severity]

    result["total_indicators"] = sum(
        len(v) for v in result["categories"].values()
    )

    result["score"] = min(total_score, 100)

    if result["score"] >= 60 or result["total_indicators"] >= 4:
        result["verdict"] = "MALICIOUS"
    elif result["score"] >= 25 or result["total_indicators"] >= 2:
        result["verdict"] = "SUSPICIOUS"
    else:
        result["verdict"] = "CLEAN"

    for cat, findings in result["categories"].items():
        if findings:
            cat_name = CATEGORY_NAMES[cat]
            highs = [f for f in findings if f["severity_int"] == 3]
            meds  = [f for f in findings if f["severity_int"] == 2]
            lows  = [f for f in findings if f["severity_int"] == 1]

            parts = []
            if highs: parts.append(f"{len(highs)} HIGH")
            if meds:  parts.append(f"{len(meds)} MEDIUM")
            if lows:  parts.append(f"{len(lows)} LOW")

            result["summary"].append(
                f"[{cat_name}] {', '.join(parts)} indicator(s) found"
            )
            # add worst finding
            worst = max(findings, key=lambda x: x["severity_int"])
            result["summary"].append(f"  → {worst['description']}")

    if not result["summary"]:
        result["summary"].append("No behavioral indicators found.")

    return result


def format_report(result: dict) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append(f"  BEHAVIORAL ANALYSIS REPORT")
    lines.append("=" * 60)
    lines.append(f"  File:       {os.path.basename(result['file'])}")
    lines.append(f"  Verdict:    {result['verdict']}")
    lines.append(f"  Score:      {result['score']}/100")
    lines.append(f"  Indicators: {result['total_indicators']}")
    lines.append("")

    for cat, findings in result["categories"].items():
        if not findings:
            continue
        cat_name = CATEGORY_NAMES[cat]
        lines.append(f"  ── {cat_name} ({'─' * (40 - len(cat_name))})")
        for f in findings:
            sev_icon = {"HIGH": "⚠", "MEDIUM": "●", "LOW": "○"}.get(f["severity"], "•")
            lines.append(f"    {sev_icon} [{f['severity']}] {f['description']}")
        lines.append("")

    if not any(result["categories"].values()):
        lines.append("  No indicators found — file appears clean.")

    lines.append("=" * 60)
    return "\n".join(lines)

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m core.behavior_monitor <file_path>")
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"File not found: {path}")
        sys.exit(1)

    report = analyze(path)
    print(format_report(report))
