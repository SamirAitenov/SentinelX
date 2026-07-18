import os
import sqlite3
import sys

import psutil

from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel,
    QFileDialog, QTextEdit, QVBoxLayout, QHBoxLayout,
    QFrame, QMessageBox, QStackedWidget,
    QTableWidget, QTableWidgetItem, QComboBox,
    QHeaderView, QAbstractItemView, QLineEdit, QSizePolicy
)
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QColor

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from core.scanner import scan_directory
from core.database import get_threat_count, get_threat_counts_by_risk, delete_threat_by_file
from core.quarantine import (
    list_quarantine_files, restore_from_quarantine,
    delete_from_quarantine, QUARANTINE_FOLDER
)
from core.logger import read_events, clear_events
from core.realtime_protection import RealtimeHandler

from ai.model import predict_file, is_model_ready
from ai.trainer import train as train_model

from gui import theme
from gui.widgets import StatCard, RiskBadge, ToggleSwitch, EmptyState, apply_fade_in, section_title, section_subtitle

from watchdog.observers import Observer


NAV_ITEMS = [
    ("Dashboard",  "🛡", 0),
    ("Scan",       "🔍", 1),
    ("AI Scan",    "🤖", 6),
    ("Threats",    "⚠",  2),
    ("Quarantine", "🔒", 3),
    ("Logs",       "📜", 4),
    ("Settings",   "⚙",  5),
]


def format_size(num_bytes):
    for unit in ["B", "KB", "MB", "GB"]:
        if num_bytes < 1024:
            return f"{num_bytes:.0f} {unit}" if unit == "B" else f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TB"


class AntivirusGUI(QWidget):

    def __init__(self):
        super().__init__()

        self.cpu_data = [0] * 20
        self.ram_data = [0] * 20
        self.realtime_observer = None
        self.realtime_path = os.path.expanduser("~")

        self.setWindowTitle("SentinelX AI Antivirus")
        self.setGeometry(200, 100, 1180, 700)
        self.setMinimumSize(980, 600)
        self.setStyleSheet(theme.GLOBAL_QSS)

        self.nav_buttons = []

        self.build_ui()

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(1000)

    # ------------------------------------------------------------------ UI

    def build_ui(self):
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        main_layout.addWidget(self.build_sidebar())

        self.stack = QStackedWidget()
        self.dashboard_page   = self.build_dashboard_page()
        self.scan_page        = self.build_scan_page()
        self.threats_page     = self.build_threats_page()
        self.quarantine_page  = self.build_quarantine_page()
        self.logs_page        = self.build_logs_page()
        self.settings_page    = self.build_settings_page()
        self.ai_scan_page     = self.build_ai_scan_page()

        # indices must match NAV_ITEMS: 0=dash 1=scan 2=threats 3=quar 4=logs 5=settings 6=ai
        for page in [
            self.dashboard_page, self.scan_page, self.threats_page,
            self.quarantine_page, self.logs_page, self.settings_page,
            self.ai_scan_page,
        ]:
            self.stack.addWidget(page)

        main_layout.addWidget(self.stack, 1)
        self.setLayout(main_layout)

        self.switch_page(0)
        self.refresh_all_data()

    def build_sidebar(self):
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(230)
        sidebar.setStyleSheet(theme.SIDEBAR_QSS)

        layout = QVBoxLayout()
        layout.setContentsMargins(16, 20, 16, 20)
        layout.setSpacing(4)

        title = QLabel("🛡 SENTINELX")
        title.setStyleSheet(f"""
            font-size: 20px;
            font-weight: 800;
            color: {theme.ACCENT};
            padding: 10px 8px 4px 8px;
            border: none;
        """)
        layout.addWidget(title)

        subtitle = QLabel("AI ANTIVIRUS")
        subtitle.setStyleSheet(f"""
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 2px;
            color: {theme.TEXT_DIM};
            padding: 0px 8px 18px 8px;
            border: none;
        """)
        layout.addWidget(subtitle)

        for name, icon, index in NAV_ITEMS:
            button = QPushButton(f"  {icon}   {name}")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setStyleSheet(theme.NAV_BUTTON_QSS)
            button.clicked.connect(lambda checked, i=index: self.switch_page(i))
            layout.addWidget(button)
            self.nav_buttons.append(button)

        layout.addStretch()

        # live protection status pill, always visible at the bottom of the sidebar
        self.sidebar_status = QLabel("● PROTECTED")
        self.sidebar_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.sidebar_status.setStyleSheet(f"""
            color: {theme.SAFE};
            border: 1px solid {theme.SAFE};
            border-radius: 8px;
            padding: 8px;
            font-weight: 700;
            font-size: 11px;
        """)
        layout.addWidget(self.sidebar_status)

        sidebar.setLayout(layout)
        return sidebar

    def switch_page(self, index):
        self.stack.setCurrentIndex(index)

        # highlight the nav button whose page index matches
        for i, button in enumerate(self.nav_buttons):
            page_index = NAV_ITEMS[i][2]
            button.setStyleSheet(
                theme.NAV_BUTTON_ACTIVE_QSS if page_index == index
                else theme.NAV_BUTTON_QSS
            )

        apply_fade_in(self.stack.currentWidget())

        refreshers = {
            2: self.load_threats,
            3: self.load_quarantine,
            4: self.load_logs,
            6: self._refresh_ai_status,
        }
        if index in refreshers:
            refreshers[index]()

    def refresh_all_data(self):
        self.load_threats()
        self.load_quarantine()
        self.load_logs()
        self.update_dashboard_counts()

    # ------------------------------------------------------------ Dashboard

    def build_dashboard_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(16)
        page.setLayout(layout)

        header = QHBoxLayout()
        header_text_widget = QWidget()
        header_text = QVBoxLayout()
        header_text.setContentsMargins(0, 0, 0, 0)
        header_text.setSpacing(2)
        header_text.addWidget(section_title("Dashboard"))
        header_text.addWidget(section_subtitle("Live overview of your system's protection status."))
        header_text_widget.setLayout(header_text)
        header_text_widget.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        header.addWidget(header_text_widget)
        header.addStretch()

        self.status_pill = QLabel("●  SYSTEM PROTECTED")
        self.status_pill.setStyleSheet(f"""
            font-size: 14px;
            color: {theme.SAFE};
            font-weight: 800;
            background-color: rgba(0, 255, 153, 0.12);
            border: 1px solid {theme.SAFE};
            border-radius: 18px;
            padding: 10px 18px;
        """)
        header.addWidget(self.status_pill, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header)

        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(14)
        self.cpu_card = StatCard("CPU Usage", "0%", theme.ACCENT)
        self.ram_card = StatCard("RAM Usage", "0%", theme.ACCENT)
        self.threat_card = StatCard("Threats Blocked", "0", theme.DANGER)
        self.quarantine_card = StatCard("In Quarantine", "0", theme.WARNING)
        for card in [self.cpu_card, self.ram_card, self.threat_card, self.quarantine_card]:
            stats_layout.addWidget(card)
        layout.addLayout(stats_layout)

        body_layout = QHBoxLayout()
        body_layout.setSpacing(14)

        chart_card = QFrame()
        chart_card.setStyleSheet(theme.CARD_QSS)
        chart_layout = QVBoxLayout()
        chart_layout.setContentsMargins(18, 16, 18, 16)
        chart_title = QLabel("RESOURCE MONITOR")
        chart_title.setStyleSheet(f"color: {theme.TEXT_DIM}; font-size: 11px; font-weight: 700; letter-spacing: 1px; border: none;")
        chart_layout.addWidget(chart_title)

        self.figure = Figure(figsize=(5, 3))
        self.canvas = FigureCanvas(self.figure)
        chart_layout.addWidget(self.canvas)
        chart_card.setLayout(chart_layout)
        body_layout.addWidget(chart_card, 3)

        process_card = QFrame()
        process_card.setStyleSheet(theme.CARD_QSS)
        process_layout = QVBoxLayout()
        process_layout.setContentsMargins(18, 16, 18, 16)
        process_title = QLabel("TOP PROCESSES")
        process_title.setStyleSheet(f"color: {theme.TEXT_DIM}; font-size: 11px; font-weight: 700; letter-spacing: 1px; border: none;")
        process_layout.addWidget(process_title)

        self.process_output = QTextEdit()
        self.process_output.setReadOnly(True)
        self.process_output.setStyleSheet(theme.TEXTEDIT_QSS)
        process_layout.addWidget(self.process_output)
        process_card.setLayout(process_layout)
        body_layout.addWidget(process_card, 2)

        layout.addLayout(body_layout, 1)

        return page

    def update_dashboard_counts(self):
        threat_count = get_threat_count()
        self.threat_card.set_value(threat_count)

        quarantine_count = len(list_quarantine_files())
        self.quarantine_card.set_value(quarantine_count)

        if self.realtime_observer is not None:
            self.status_pill.setText("●  SYSTEM PROTECTED")
            self.status_pill.setStyleSheet(f"""
                font-size: 14px; color: {theme.SAFE}; font-weight: 800;
                background-color: rgba(0, 255, 153, 0.12);
                border: 1px solid {theme.SAFE}; border-radius: 18px; padding: 10px 18px;
            """)
            self.sidebar_status.setText("● PROTECTED")
            self.sidebar_status.setStyleSheet(f"""
                color: {theme.SAFE}; border: 1px solid {theme.SAFE};
                border-radius: 8px; padding: 8px; font-weight: 700; font-size: 11px;
            """)
        else:
            self.status_pill.setText("●  REALTIME PROTECTION OFF")
            self.status_pill.setStyleSheet(f"""
                font-size: 14px; color: {theme.WARNING}; font-weight: 800;
                background-color: rgba(255, 176, 32, 0.12);
                border: 1px solid {theme.WARNING}; border-radius: 18px; padding: 10px 18px;
            """)
            self.sidebar_status.setText("● MONITOR OFF")
            self.sidebar_status.setStyleSheet(f"""
                color: {theme.WARNING}; border: 1px solid {theme.WARNING};
                border-radius: 8px; padding: 8px; font-weight: 700; font-size: 11px;
            """)

    # ----------------------------------------------------------------- Scan

    def build_scan_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(16)
        page.setLayout(layout)

        layout.addWidget(section_title("Scan"))
        layout.addWidget(section_subtitle("Choose a folder to check every file for suspicious hashes and behaviour."))

        button_row = QHBoxLayout()
        self.scan_button = QPushButton("📁  SCAN A FOLDER")
        self.scan_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_button.setStyleSheet(theme.PRIMARY_BUTTON_QSS)
        self.scan_button.clicked.connect(self.scan_directory)
        button_row.addWidget(self.scan_button)

        self.clear_scan_button = QPushButton("Clear output")
        self.clear_scan_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_scan_button.setStyleSheet(theme.SECONDARY_BUTTON_QSS)
        self.clear_scan_button.clicked.connect(lambda: self.output.clear())
        button_row.addWidget(self.clear_scan_button)
        button_row.addStretch()
        layout.addLayout(button_row)

        self.scan_progress_label = QLabel("")
        self.scan_progress_label.setStyleSheet(f"color: {theme.TEXT_DIM}; font-size: 12px; border: none;")
        layout.addWidget(self.scan_progress_label)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet(theme.TEXTEDIT_QSS)
        self.output.setPlaceholderText("Scan results will appear here…")
        layout.addWidget(self.output, 1)

        return page

    def scan_directory(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")

        if not folder:
            return

        self.scan_button.setEnabled(False)
        self.scan_button.setText("SCANNING…")
        self.scan_progress_label.setText(f"Scanning: {folder}")
        QApplication.processEvents()

        self.output.append(f'<span style="color:{theme.ACCENT}">▶ Scanning: {folder}</span>')

        try:
            results = scan_directory(folder)
        except Exception as e:
            self.output.append(f'<span style="color:{theme.DANGER}">Scan failed: {e}</span>')
            results = []

        if not results:
            self.output.append(f'<span style="color:{theme.SAFE}">✔ No threats found.</span>')
        else:
            for result in results:
                color = theme.risk_color(result["risk"])
                threats_text = ", ".join(result["threats"])
                self.output.append(
                    f'<div style="margin-top:8px;">'
                    f'<span style="color:{color}; font-weight:bold;">⚠ THREAT DETECTED [{result["risk"]}]</span><br>'
                    f'<span style="color:{theme.TEXT}">File: {result["file"]}</span><br>'
                    f'<span style="color:{theme.TEXT_DIM}">Reason: {threats_text}</span>'
                    f'</div>'
                )

        self.scan_progress_label.setText(f"Last scan: {folder}  ·  {len(results)} threat(s) found")
        self.scan_button.setEnabled(True)
        self.scan_button.setText("📁  SCAN A FOLDER")

        self.refresh_all_data()

    # -------------------------------------------------------------- Threats

    def build_threats_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(14)
        page.setLayout(layout)

        layout.addWidget(section_title("Threats"))
        layout.addWidget(section_subtitle("Every threat detected during a scan or by realtime protection."))

        filter_row = QHBoxLayout()
        filter_label = QLabel("Filter by risk:")
        filter_label.setStyleSheet(f"color: {theme.TEXT_DIM}; border: none; font-size: 13px;")
        filter_row.addWidget(filter_label)

        self.filter_box = QComboBox()
        self.filter_box.addItems(["ALL", "HIGH", "MEDIUM", "LOW"])
        self.filter_box.setStyleSheet(theme.COMBO_QSS)
        self.filter_box.setFixedWidth(140)
        self.filter_box.currentTextChanged.connect(self.load_threats)
        filter_row.addWidget(self.filter_box)
        filter_row.addStretch()

        self.threats_count_label = QLabel("")
        self.threats_count_label.setStyleSheet(f"color: {theme.TEXT_DIM}; border: none; font-size: 12px;")
        filter_row.addWidget(self.threats_count_label)

        layout.addLayout(filter_row)

        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(4)
        self.threats_table.setHorizontalHeaderLabels(["ID", "File", "Risk", "Date"])
        self.threats_table.setStyleSheet(theme.TABLE_QSS)
        self.threats_table.setAlternatingRowColors(True)
        self.threats_table.verticalHeader().setVisible(False)
        self.threats_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.threats_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.threats_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.threats_table.setColumnWidth(0, 60)
        self.threats_table.setColumnWidth(2, 110)
        self.threats_table.setColumnWidth(3, 170)
        layout.addWidget(self.threats_table, 1)

        self.threats_empty = EmptyState(
            "🛡", "No threats recorded",
            "Run a scan or enable realtime protection to start tracking threats here."
        )
        layout.addWidget(self.threats_empty, 1)

        return page

    def load_threats(self):
        conn = sqlite3.connect("sentinelx.db")
        cursor = conn.cursor()
        selected = self.filter_box.currentText()

        if selected == "ALL":
            cursor.execute("SELECT * FROM threats ORDER BY id DESC")
        else:
            cursor.execute(
                "SELECT * FROM threats WHERE risk = ? ORDER BY id DESC",
                (selected,)
            )

        rows = cursor.fetchall()
        conn.close()

        self.threats_table.setRowCount(0)
        self.threats_table.setRowCount(len(rows))

        for i, row in enumerate(rows):
            row_id, file_path, risk, date = row

            id_item = QTableWidgetItem(str(row_id))
            id_item.setForeground(QColor(theme.TEXT_DIM))
            self.threats_table.setItem(i, 0, id_item)

            file_item = QTableWidgetItem(file_path)
            file_item.setToolTip(file_path)
            self.threats_table.setItem(i, 1, file_item)

            risk_item = QTableWidgetItem(risk)
            risk_color = QColor(theme.risk_color(risk))
            risk_item.setForeground(risk_color)
            font = risk_item.font()
            font.setBold(True)
            risk_item.setFont(font)
            self.threats_table.setItem(i, 2, risk_item)

            date_item = QTableWidgetItem(str(date))
            date_item.setForeground(QColor(theme.TEXT_DIM))
            self.threats_table.setItem(i, 3, date_item)

        has_rows = len(rows) > 0
        self.threats_table.setVisible(has_rows)
        self.threats_empty.setVisible(not has_rows)

        if not has_rows:
            if selected == "ALL":
                self.threats_empty.set_text(
                    "🛡", "No threats recorded",
                    "Run a scan or enable realtime protection to start tracking threats here."
                )
            else:
                self.threats_empty.set_text(
                    "🛡", f"No {selected} risk threats",
                    f"Nothing currently classified as {selected}. Try a different filter."
                )
        self.threats_count_label.setText(f"{len(rows)} record(s)")

    # ----------------------------------------------------------- Quarantine

    def build_quarantine_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(14)
        page.setLayout(layout)

        header_row = QHBoxLayout()
        header_text_widget = QWidget()
        header_text = QVBoxLayout()
        header_text.setContentsMargins(0, 0, 0, 0)
        header_text.setSpacing(2)
        header_text.addWidget(section_title("Quarantine"))
        header_text.addWidget(section_subtitle("Files isolated here can no longer run. Restore them or delete them for good."))
        header_text_widget.setLayout(header_text)
        header_text_widget.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        header_row.addWidget(header_text_widget)
        header_row.addStretch()

        refresh_button = QPushButton("⟳  Refresh")
        refresh_button.setCursor(Qt.CursorShape.PointingHandCursor)
        refresh_button.setStyleSheet(theme.SECONDARY_BUTTON_QSS)
        refresh_button.clicked.connect(self.load_quarantine)
        header_row.addWidget(refresh_button, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header_row)

        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(4)
        self.quarantine_table.setHorizontalHeaderLabels(["File", "Size", "Quarantined", "Actions"])
        self.quarantine_table.setStyleSheet(theme.TABLE_QSS)
        self.quarantine_table.setAlternatingRowColors(True)
        self.quarantine_table.verticalHeader().setVisible(False)
        self.quarantine_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.quarantine_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.quarantine_table.setColumnWidth(1, 90)
        self.quarantine_table.setColumnWidth(2, 160)
        self.quarantine_table.setColumnWidth(3, 160)
        layout.addWidget(self.quarantine_table, 1)

        self.quarantine_empty = EmptyState(
            "🔒", "Quarantine is empty",
            "Dangerous files found during a scan or by realtime protection will show up here."
        )
        layout.addWidget(self.quarantine_empty, 1)

        return page

    def load_quarantine(self):
        files = list_quarantine_files()

        self.quarantine_table.setRowCount(0)
        self.quarantine_table.setRowCount(len(files))

        for i, item in enumerate(files):
            name_item = QTableWidgetItem(item["name"])
            name_item.setToolTip(item["path"])
            self.quarantine_table.setItem(i, 0, name_item)

            size_item = QTableWidgetItem(format_size(item["size"]))
            size_item.setForeground(QColor(theme.TEXT_DIM))
            self.quarantine_table.setItem(i, 1, size_item)

            date_item = QTableWidgetItem(item["date"])
            date_item.setForeground(QColor(theme.TEXT_DIM))
            self.quarantine_table.setItem(i, 2, date_item)

            actions = QWidget()
            actions_layout = QHBoxLayout()
            actions_layout.setContentsMargins(6, 4, 6, 4)
            actions_layout.setSpacing(6)

            restore_btn = QPushButton("Restore")
            restore_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            restore_btn.setStyleSheet(theme.TABLE_ACTION_SAFE_QSS)
            restore_btn.clicked.connect(lambda checked, name=item["name"]: self.handle_restore(name))
            actions_layout.addWidget(restore_btn)

            delete_btn = QPushButton("Delete")
            delete_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            delete_btn.setStyleSheet(theme.TABLE_ACTION_DANGER_QSS)
            delete_btn.clicked.connect(lambda checked, name=item["name"]: self.handle_delete(name))
            actions_layout.addWidget(delete_btn)

            actions.setLayout(actions_layout)
            self.quarantine_table.setCellWidget(i, 3, actions)
            self.quarantine_table.setRowHeight(i, 44)

        has_rows = len(files) > 0
        self.quarantine_table.setVisible(has_rows)
        self.quarantine_empty.setVisible(not has_rows)

        self.update_dashboard_counts()

    def handle_restore(self, filename):
        confirm = QMessageBox.question(
            self, "Restore file",
            f"Restore \"{filename}\" to its original location?\n\n"
            f"Only do this if you're sure it isn't actually malicious.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        original_path = os.path.join(QUARANTINE_FOLDER, filename)
        ok = restore_from_quarantine(filename)

        if ok:
            delete_threat_by_file(original_path)
            QMessageBox.information(self, "Restored", f"\"{filename}\" has been restored.")
        else:
            QMessageBox.warning(self, "Restore failed", f"Could not restore \"{filename}\".")

        self.load_quarantine()
        self.load_threats()
        self.load_logs()

    def handle_delete(self, filename):
        confirm = QMessageBox.question(
            self, "Delete permanently",
            f"Permanently delete \"{filename}\"? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        ok = delete_from_quarantine(filename)

        if not ok:
            QMessageBox.warning(self, "Delete failed", f"Could not delete \"{filename}\".")

        self.load_quarantine()
        self.load_logs()

    # ----------------------------------------------------------------- Logs

    def build_logs_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(14)
        page.setLayout(layout)

        header_row = QHBoxLayout()
        header_text_widget = QWidget()
        header_text = QVBoxLayout()
        header_text.setContentsMargins(0, 0, 0, 0)
        header_text.setSpacing(2)
        header_text.addWidget(section_title("Logs"))
        header_text.addWidget(section_subtitle("A timestamped record of everything SentinelX has done."))
        header_text_widget.setLayout(header_text)
        header_text_widget.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        header_row.addWidget(header_text_widget)
        header_row.addStretch()

        clear_button = QPushButton("Clear log")
        clear_button.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_button.setStyleSheet(theme.DANGER_BUTTON_QSS)
        clear_button.clicked.connect(self.handle_clear_logs)
        header_row.addWidget(clear_button, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header_row)

        self.log_search = QLineEdit()
        self.log_search.setPlaceholderText("Search logs…")
        self.log_search.setStyleSheet(theme.LINE_EDIT_QSS)
        self.log_search.textChanged.connect(self.load_logs)
        layout.addWidget(self.log_search)

        self.logs_output = QTextEdit()
        self.logs_output.setReadOnly(True)
        self.logs_output.setStyleSheet(theme.TEXTEDIT_QSS)
        layout.addWidget(self.logs_output, 1)

        self.logs_empty = EmptyState(
            "📜", "No activity yet",
            "Scan a folder or enable realtime protection to start generating logs."
        )
        layout.addWidget(self.logs_empty, 1)

        return page

    def load_logs(self):
        events = read_events(limit=300)
        query = self.log_search.text().strip().lower() if hasattr(self, "log_search") else ""

        if query:
            events = [e for e in events if query in e.lower()]

        if not events:
            self.logs_output.setVisible(False)
            self.logs_empty.setVisible(True)
            if query:
                self.logs_empty.set_text(
                    "🔎", "No matching logs",
                    f"Nothing in the log matches \"{self.log_search.text().strip()}\". Try a different search term."
                )
            else:
                self.logs_empty.set_text(
                    "📜", "No activity yet",
                    "Scan a folder or enable realtime protection to start generating logs."
                )
            return

        self.logs_output.setVisible(True)
        self.logs_empty.setVisible(False)

        lines = []
        for event in events:
            color = theme.TEXT_DIM
            if "threat" in event.lower() or "blocked" in event.lower() or "error" in event.lower():
                color = theme.DANGER
            elif "quarantine" in event.lower():
                color = theme.WARNING
            elif "restored" in event.lower() or "enabled" in event.lower():
                color = theme.SAFE
            lines.append(f'<span style="color:{color}">{event}</span>')

        self.logs_output.setHtml("<br>".join(lines))

    def handle_clear_logs(self):
        confirm = QMessageBox.question(
            self, "Clear logs",
            "Clear the entire activity log? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
        )
        if confirm == QMessageBox.StandardButton.Yes:
            clear_events()
            self.load_logs()

    # ------------------------------------------------------------- Settings

    def build_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(16)
        page.setLayout(layout)

        layout.addWidget(section_title("Settings"))
        layout.addWidget(section_subtitle("Configure how SentinelX watches and protects your system."))

        # --- Realtime protection card -----------------------------------
        rt_card = QFrame()
        rt_card.setStyleSheet(theme.CARD_QSS)
        rt_layout = QVBoxLayout()
        rt_layout.setContentsMargins(20, 18, 20, 18)
        rt_layout.setSpacing(10)

        rt_top = QHBoxLayout()
        rt_text = QVBoxLayout()
        rt_text.setSpacing(2)
        rt_title = QLabel("Realtime Protection")
        rt_title.setStyleSheet(f"font-size: 15px; font-weight: 700; color: {theme.TEXT}; border: none;")
        rt_text.addWidget(rt_title)
        rt_desc = QLabel("Watches a folder continuously and scans every new file the instant it appears.")
        rt_desc.setStyleSheet(f"font-size: 12px; color: {theme.TEXT_DIM}; border: none;")
        rt_desc.setWordWrap(True)
        rt_text.addWidget(rt_desc)
        rt_top.addLayout(rt_text)
        rt_top.addStretch()

        self.realtime_toggle = ToggleSwitch(checked=False)
        self.realtime_toggle.toggled.connect(self.handle_realtime_toggle)
        rt_top.addWidget(self.realtime_toggle, 0, Qt.AlignmentFlag.AlignTop)
        rt_layout.addLayout(rt_top)

        path_row = QHBoxLayout()
        self.realtime_path_label = QLabel(f"Watching: {self.realtime_path}")
        self.realtime_path_label.setStyleSheet(f"font-size: 12px; color: {theme.ACCENT_DIM}; border: none;")
        path_row.addWidget(self.realtime_path_label, 1)

        choose_path_btn = QPushButton("Change folder")
        choose_path_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        choose_path_btn.setStyleSheet(theme.SECONDARY_BUTTON_QSS)
        choose_path_btn.clicked.connect(self.handle_choose_realtime_path)
        path_row.addWidget(choose_path_btn)
        rt_layout.addLayout(path_row)

        rt_card.setLayout(rt_layout)
        layout.addWidget(rt_card)

        # --- About card ----------------------------------------------------
        about_card = QFrame()
        about_card.setStyleSheet(theme.CARD_QSS)
        about_layout = QVBoxLayout()
        about_layout.setContentsMargins(20, 18, 20, 18)
        about_layout.setSpacing(6)

        about_title = QLabel("About SentinelX")
        about_title.setStyleSheet(f"font-size: 15px; font-weight: 700; color: {theme.TEXT}; border: none;")
        about_layout.addWidget(about_title)

        about_text = QLabel(
            "SentinelX combines hash matching and heuristic analysis to flag suspicious files, "
            "moves anything dangerous into quarantine, and keeps a full activity log of what it did and when."
        )
        about_text.setWordWrap(True)
        about_text.setStyleSheet(f"font-size: 12px; color: {theme.TEXT_DIM}; border: none;")
        about_layout.addWidget(about_text)

        version_label = QLabel("Version 1.0  ·  Engine: Hash + Heuristic")
        version_label.setStyleSheet(f"font-size: 11px; color: {theme.TEXT_DIM}; border: none; padding-top: 6px;")
        about_layout.addWidget(version_label)

        about_card.setLayout(about_layout)
        layout.addWidget(about_card)

        layout.addStretch()
        return page

    def handle_choose_realtime_path(self):
        folder = QFileDialog.getExistingDirectory(self, "Select folder to monitor", self.realtime_path)
        if folder:
            self.realtime_path = folder
            self.realtime_path_label.setText(f"Watching: {self.realtime_path}")

            if self.realtime_observer is not None:
                self.stop_realtime_protection()
                self.start_realtime_protection()

    def handle_realtime_toggle(self, checked):
        if checked:
            self.start_realtime_protection()
        else:
            self.stop_realtime_protection()

    def start_realtime_protection(self):
        if self.realtime_observer is not None:
            return

        try:
            handler = RealtimeHandler()
            observer = Observer()
            observer.schedule(handler, self.realtime_path, recursive=True)
            observer.start()
            self.realtime_observer = observer

            from core.logger import log_event
            log_event(f"Realtime protection enabled on: {self.realtime_path}")

        except Exception as e:
            QMessageBox.warning(self, "Could not start protection", str(e))
            self.realtime_toggle.setChecked(False)

        self.update_dashboard_counts()
        self.load_logs()

    def stop_realtime_protection(self):
        if self.realtime_observer is not None:
            try:
                self.realtime_observer.stop()
                self.realtime_observer.join(timeout=2)
            except Exception:
                pass
            self.realtime_observer = None

            from core.logger import log_event
            log_event("Realtime protection disabled")

        self.update_dashboard_counts()
        self.load_logs()

    # ------------------------------------------------------------ Live stats

    def get_processes(self):
        processes = []

        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                name = proc.info['name']
                cpu = proc.info['cpu_percent'] or 0
                processes.append((name, cpu))
            except Exception:
                continue

        processes.sort(key=lambda x: x[1], reverse=True)
        return processes[:10]

    def update_stats(self):
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent

        self.cpu_card.set_value(f"{cpu:.0f}%")
        self.ram_card.set_value(f"{ram:.0f}%")
        self.update_dashboard_counts()

        self.cpu_data.append(cpu)
        self.cpu_data.pop(0)
        self.ram_data.append(ram)
        self.ram_data.pop(0)

        self.figure.clear()
        ax = self.figure.add_subplot(111)
        ax.plot(self.cpu_data, label="CPU", color=theme.ACCENT, linewidth=1.6)
        ax.plot(self.ram_data, label="RAM", color=theme.WARNING, linewidth=1.6)
        ax.set_facecolor(theme.PANEL)
        ax.set_ylim(0, 100)
        self.figure.patch.set_facecolor(theme.PANEL)
        ax.tick_params(colors=theme.TEXT_DIM, labelsize=8)
        for spine in ax.spines.values():
            spine.set_color(theme.BORDER)
        ax.legend(facecolor=theme.PANEL, labelcolor=theme.TEXT, fontsize=8, frameon=False)
        ax.grid(True, color=theme.BORDER, linewidth=0.5, alpha=0.5)
        self.figure.tight_layout()
        self.canvas.draw()

        processes = self.get_processes()
        lines = ["TOP PROCESSES", ""]
        for name, cpu in processes:
            marker = " ⚠" if cpu > 50 else ""
            lines.append(f"{name:<28} {cpu:>5.1f}%{marker}")
        self.process_output.setText("\n".join(lines))

    def closeEvent(self, event):
        self.stop_realtime_protection()
        event.accept()

    # ------------------------------------------------------------ AI Scan

    def build_ai_scan_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(16)
        page.setLayout(layout)

        layout.addWidget(section_title("AI Scan"))
        layout.addWidget(section_subtitle(
            "RandomForest model analyses 15 numeric features of each file — "
            "size, entropy, keyword density, base64 content and more — "
            "to classify it independently of keyword matching."
        ))

        # ---- model status card --------------------------------------------
        self.ai_status_card = QFrame()
        self.ai_status_card.setStyleSheet(theme.CARD_QSS)
        status_layout = QHBoxLayout()
        status_layout.setContentsMargins(20, 16, 20, 16)

        self.ai_status_icon  = QLabel("🤖")
        self.ai_status_icon.setStyleSheet("font-size: 28px; border: none;")
        status_layout.addWidget(self.ai_status_icon)

        status_text = QVBoxLayout()
        status_text.setSpacing(2)
        self.ai_status_title = QLabel()
        self.ai_status_title.setStyleSheet(
            f"font-size: 15px; font-weight: 700; color: {theme.TEXT}; border: none;"
        )
        self.ai_status_desc = QLabel()
        self.ai_status_desc.setStyleSheet(
            f"font-size: 12px; color: {theme.TEXT_DIM}; border: none;"
        )
        status_text.addWidget(self.ai_status_title)
        status_text.addWidget(self.ai_status_desc)
        status_layout.addLayout(status_text, 1)

        self.ai_train_button = QPushButton("Train model now")
        self.ai_train_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ai_train_button.setStyleSheet(theme.PRIMARY_BUTTON_QSS)
        self.ai_train_button.clicked.connect(self.handle_train_model)
        status_layout.addWidget(self.ai_train_button, 0, Qt.AlignmentFlag.AlignRight)

        self.ai_status_card.setLayout(status_layout)
        layout.addWidget(self.ai_status_card)

        # ---- scan controls ------------------------------------------------
        btn_row = QHBoxLayout()

        self.ai_scan_file_btn = QPushButton("🔬  SCAN A FILE")
        self.ai_scan_file_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ai_scan_file_btn.setStyleSheet(theme.PRIMARY_BUTTON_QSS)
        self.ai_scan_file_btn.clicked.connect(self.handle_ai_scan_file)
        btn_row.addWidget(self.ai_scan_file_btn)

        self.ai_scan_folder_btn = QPushButton("📁  SCAN A FOLDER")
        self.ai_scan_folder_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ai_scan_folder_btn.setStyleSheet(theme.SECONDARY_BUTTON_QSS)
        self.ai_scan_folder_btn.clicked.connect(self.handle_ai_scan_folder)
        btn_row.addWidget(self.ai_scan_folder_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_btn.setStyleSheet(theme.SECONDARY_BUTTON_QSS)
        clear_btn.clicked.connect(lambda: (
            self.ai_results_table.setRowCount(0),
            self.ai_summary_label.setText("")
        ))
        btn_row.addWidget(clear_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # refresh status NOW — after the scan buttons are created
        self._refresh_ai_status()

        self.ai_summary_label = QLabel("")
        self.ai_summary_label.setStyleSheet(
            f"color: {theme.TEXT_DIM}; font-size: 12px; border: none;"
        )
        layout.addWidget(self.ai_summary_label)

        # ---- results table ------------------------------------------------
        self.ai_results_table = QTableWidget()
        self.ai_results_table.setColumnCount(5)
        self.ai_results_table.setHorizontalHeaderLabels(
            ["File", "AI Label", "Confidence", "Risk", "Top signal"]
        )
        self.ai_results_table.setStyleSheet(theme.TABLE_QSS)
        self.ai_results_table.setAlternatingRowColors(True)
        self.ai_results_table.verticalHeader().setVisible(False)
        self.ai_results_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.ai_results_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.ai_results_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.ai_results_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        self.ai_results_table.setColumnWidth(1, 100)
        self.ai_results_table.setColumnWidth(2, 110)
        self.ai_results_table.setColumnWidth(3, 80)
        layout.addWidget(self.ai_results_table, 1)

        return page

    def _refresh_ai_status(self):
        ready = is_model_ready()
        if ready:
            self.ai_status_title.setText("Model ready")
            self.ai_status_title.setStyleSheet(
                f"font-size: 15px; font-weight: 700; color: {theme.SAFE}; border: none;"
            )
            from ai.model import get_model_info
            self.ai_status_desc.setText(get_model_info() + " · model.pkl loaded from ai/")
            self.ai_train_button.setText("Retrain model")
            self.ai_scan_file_btn.setEnabled(True)
            self.ai_scan_folder_btn.setEnabled(True)
        else:
            self.ai_status_title.setText("Model not trained yet")
            self.ai_status_title.setStyleSheet(
                f"font-size: 15px; font-weight: 700; color: {theme.WARNING}; border: none;"
            )
            self.ai_status_desc.setText(
                "Click 'Train model now' to generate a synthetic dataset and train "
                "the RandomForest classifier. Takes about 10–20 seconds."
            )
            self.ai_train_button.setText("Train model now")
            self.ai_scan_file_btn.setEnabled(False)
            self.ai_scan_folder_btn.setEnabled(False)

    def handle_train_model(self):
        self.ai_train_button.setEnabled(False)
        self.ai_train_button.setText("Training…")
        self.ai_status_desc.setText("Generating dataset and training — please wait…")
        QApplication.processEvents()

        import threading

        def _train():
            try:
                train_model(n_malware=400, n_safe=400)
            except Exception as e:
                from core.logger import log_event
                log_event(f"AI training error: {e}")
            finally:
                # UI updates must happen on the main thread
                QTimer.singleShot(0, self._on_training_done)

        threading.Thread(target=_train, daemon=True).start()

    def _on_training_done(self):
        # reload the model cache
        import ai.model as _m
        _m._model  = None
        _m._scaler = None

        self.ai_train_button.setEnabled(True)
        self._refresh_ai_status()
        from core.logger import log_event
        log_event("AI model trained successfully")
        self.load_logs()

    def _ai_top_signal(self, features: dict) -> str:
        """Returns a short human-readable explanation of what drove the verdict."""
        checks = [
            (features.get("keyword_count", 0) >= 3,       f"keywords ×{int(features['keyword_count'])}"),
            (features.get("base64_score", 0) >= 0.4,      "base64 payload"),
            (features.get("url_count", 0) >= 1,           f"URLs ×{int(features['url_count'])}"),
            (features.get("entropy", 0) >= 6.5,           f"entropy {features['entropy']:.1f}"),
            (features.get("ip_count", 0) >= 1,            f"IP addresses ×{int(features['ip_count'])}"),
            (features.get("suspicious_ext", 0) == 1.0,    "suspicious extension"),
            (features.get("non_ascii_ratio", 0) >= 0.3,   "high non-ASCII ratio"),
            (features.get("unique_line_ratio", 0) <= 0.3, "low unique-line ratio"),
        ]
        signals = [desc for cond, desc in checks if cond]
        return ", ".join(signals[:3]) if signals else "general pattern"

    def _add_ai_result_row(self, file_path: str, result: dict):
        row = self.ai_results_table.rowCount()
        self.ai_results_table.insertRow(row)

        # File
        name_item = QTableWidgetItem(os.path.basename(file_path))
        name_item.setToolTip(file_path)
        self.ai_results_table.setItem(row, 0, name_item)

        # Label
        label     = result["label"]
        label_color = theme.DANGER if label == "MALWARE" else theme.SAFE
        label_item = QTableWidgetItem(label)
        label_item.setForeground(QColor(label_color))
        f = label_item.font(); f.setBold(True); label_item.setFont(f)
        self.ai_results_table.setItem(row, 1, label_item)

        # Confidence
        conf_item = QTableWidgetItem(f"{result['confidence']:.0%}")
        conf_item.setForeground(QColor(theme.TEXT_DIM))
        self.ai_results_table.setItem(row, 2, conf_item)

        # Risk
        risk       = result["risk"]
        risk_color = theme.risk_color(risk)
        risk_item  = QTableWidgetItem(risk)
        risk_item.setForeground(QColor(risk_color))
        f = risk_item.font(); f.setBold(True); risk_item.setFont(f)
        self.ai_results_table.setItem(row, 3, risk_item)

        # Top signal
        signal_item = QTableWidgetItem(self._ai_top_signal(result["features"]))
        signal_item.setForeground(QColor(theme.TEXT_DIM))
        self.ai_results_table.setItem(row, 4, signal_item)

    def handle_ai_scan_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select file to scan")
        if not path:
            return

        result = predict_file(path)
        if result is None:
            QMessageBox.warning(self, "Scan failed", f"Could not read file:\n{path}")
            return

        self._add_ai_result_row(path, result)
        self.ai_summary_label.setText(
            f"Last scan: {os.path.basename(path)}  ·  "
            f"AI verdict: {result['label']} ({result['confidence']:.0%})"
        )

    def handle_ai_scan_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select folder")
        if not folder:
            return

        self.ai_scan_folder_btn.setEnabled(False)
        self.ai_scan_folder_btn.setText("Scanning…")
        QApplication.processEvents()

        files = []
        for root, _, fnames in os.walk(folder):
            for fname in fnames:
                files.append(os.path.join(root, fname))

        malware_count = 0
        for i, fpath in enumerate(files):
            result = predict_file(fpath)
            if result:
                self._add_ai_result_row(fpath, result)
                if result["label"] == "MALWARE":
                    malware_count += 1
            if i % 10 == 0:
                self.ai_scan_folder_btn.setText(f"Scanning… {i+1}/{len(files)}")
                QApplication.processEvents()

        self.ai_summary_label.setText(
            f"Scanned {len(files)} files · "
            f"{malware_count} malware detected · "
            f"{len(files) - malware_count} safe"
        )
        self.ai_scan_folder_btn.setEnabled(True)
        self.ai_scan_folder_btn.setText("📁  SCAN A FOLDER")


def run_gui():
    app = QApplication(sys.argv)
    window = AntivirusGUI()
    window.show()
    sys.exit(app.exec())