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
from core.behevior_monitor import analyze as behavior_analyze, format_report as behavior_format, CATEGORY_NAMES

from gui import theme
from gui.widgets import StatCard, RiskBadge, ToggleSwitch, EmptyState, apply_fade_in, section_title, section_subtitle
from gui import translations as tr

from watchdog.observers import Observer


def _nav_items():
    return [
        (tr.get("nav_dashboard"),  "🛡", 0),
        (tr.get("nav_scan"),       "🔍", 1),
        (tr.get("nav_ai_scan"),    "🤖", 6),
        (tr.get("nav_behavior"),   "🧬", 7),
        (tr.get("nav_threats"),    "⚠",  2),
        (tr.get("nav_quarantine"), "🔒", 3),
        (tr.get("nav_logs"),       "📜", 4),
        (tr.get("nav_settings"),   "⚙",  5),
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
        self.behavior_page    = self.build_behavior_page()

        for page in [
            self.dashboard_page, self.scan_page, self.threats_page,
            self.quarantine_page, self.logs_page, self.settings_page,
            self.ai_scan_page, self.behavior_page,
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
            font-size: 20px; font-weight: 800; color: {theme.ACCENT};
            padding: 10px 8px 4px 8px; border: none;
        """)
        layout.addWidget(title)

        self.sidebar_subtitle = QLabel(tr.get("app_subtitle"))
        self.sidebar_subtitle.setStyleSheet(f"""
            font-size: 10px; font-weight: 700; letter-spacing: 2px;
            color: {theme.TEXT_DIM}; padding: 0px 8px 18px 8px; border: none;
        """)
        layout.addWidget(self.sidebar_subtitle)

        nav_items = _nav_items()
        self.nav_buttons = []
        for name, icon, index in nav_items:
            button = QPushButton(f"  {icon}   {name}")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setStyleSheet(theme.NAV_BUTTON_QSS)
            button.clicked.connect(lambda checked, i=index: self.switch_page(i))
            layout.addWidget(button)
            self.nav_buttons.append(button)

        layout.addStretch()

        # Кнопка смены языка
        self.lang_btn = QPushButton(tr.get("lang_button"))
        self.lang_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.lang_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {theme.ACCENT};
                border: 1px solid {theme.ACCENT};
                border-radius: 8px;
                padding: 6px;
                font-weight: 700;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: rgba(0,245,255,0.1);
            }}
        """)
        self.lang_btn.clicked.connect(self.toggle_language)
        layout.addWidget(self.lang_btn)

        self.sidebar_status = QLabel(tr.get("sidebar_monitor_off"))
        self.sidebar_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.sidebar_status.setStyleSheet(f"""
            color: {theme.SAFE}; border: 1px solid {theme.SAFE};
            border-radius: 8px; padding: 8px; font-weight: 700; font-size: 11px;
        """)
        layout.addWidget(self.sidebar_status)

        sidebar.setLayout(layout)
        return sidebar

    def toggle_language(self):
        """Переключает язык и обновляет весь интерфейс."""
        tr.toggle_lang()
        self.retranslate_ui()

    def retranslate_ui(self):
        """Обновляет все тексты интерфейса после смены языка."""
        # Кнопка языка
        self.lang_btn.setText(tr.get("lang_button"))

        # Субтитл сайдбара
        self.sidebar_subtitle.setText(tr.get("app_subtitle"))

        # Кнопки навигации
        nav_items = _nav_items()
        for i, (name, icon, _) in enumerate(nav_items):
            if i < len(self.nav_buttons):
                self.nav_buttons[i].setText(f"  {icon}   {name}")

        # Dashboard
        self._dash_title_label.setText(tr.get("dash_title"))
        self._dash_subtitle_label.setText(tr.get("dash_subtitle"))
        self.cpu_card.title_label.setText(tr.get("cpu_usage").upper())
        self.ram_card.title_label.setText(tr.get("ram_usage").upper())
        self.threat_card.title_label.setText(tr.get("threats_blocked").upper())
        self.quarantine_card.title_label.setText(tr.get("in_quarantine").upper())
        self._chart_title_label.setText(tr.get("resource_monitor"))
        self._process_title_label.setText(tr.get("top_processes"))

        # Scan
        self._scan_title_label.setText(tr.get("scan_title"))
        self._scan_subtitle_label.setText(tr.get("scan_subtitle"))
        self.scan_button.setText(tr.get("scan_folder_btn"))
        self.clear_scan_button.setText(tr.get("scan_clear_btn"))
        self.output.setPlaceholderText(tr.get("scan_placeholder"))

        # Threats
        self._threats_title_label.setText(tr.get("threats_title"))
        self._threats_subtitle_label.setText(tr.get("threats_subtitle"))
        self._filter_label.setText(tr.get("filter_by_risk"))
        self.threats_table.setHorizontalHeaderLabels([
            tr.get("col_id"), tr.get("col_file"),
            tr.get("col_risk"), tr.get("col_date")
        ])
        self.load_threats()

        # Quarantine
        self._quar_title_label.setText(tr.get("quar_title"))
        self._quar_subtitle_label.setText(tr.get("quar_subtitle"))
        self._refresh_btn.setText(tr.get("refresh_btn"))
        self.quarantine_table.setHorizontalHeaderLabels([
            tr.get("col_file"), tr.get("col_size"),
            tr.get("col_quarantined"), tr.get("col_actions")
        ])
        self.load_quarantine()

        # Logs
        self._logs_title_label.setText(tr.get("logs_title"))
        self._logs_subtitle_label.setText(tr.get("logs_subtitle"))
        self._clear_log_btn.setText(tr.get("clear_log_btn"))
        self.log_search.setPlaceholderText(tr.get("search_logs"))
        self.load_logs()

        # Settings
        self._settings_title_label.setText(tr.get("settings_title"))
        self._settings_subtitle_label.setText(tr.get("settings_subtitle"))
        self._rt_title_label.setText(tr.get("realtime_title"))
        self._rt_desc_label.setText(tr.get("realtime_desc"))
        self._change_folder_btn.setText(tr.get("change_folder_btn"))
        self._about_title_label.setText(tr.get("about_title"))
        self._about_text_label.setText(tr.get("about_text"))
        self._version_label.setText(tr.get("version_label"))
        self.realtime_path_label.setText(tr.get("watching") + self.realtime_path)

        # AI Scan
        self._ai_title_label.setText(tr.get("ai_title"))
        self._ai_subtitle_label.setText(tr.get("ai_subtitle"))
        self.ai_scan_file_btn.setText(tr.get("scan_file_btn"))
        self.ai_scan_folder_btn.setText(tr.get("scan_folder_btn_ai"))
        self._ai_clear_btn.setText(tr.get("clear_btn"))
        self.ai_results_table.setHorizontalHeaderLabels([
            tr.get("col_file"), tr.get("col_ai_label"),
            tr.get("col_confidence"), tr.get("col_risk"), tr.get("col_top_signal")
        ])
        self._refresh_ai_status()

        # Behavior
        self._beh_title_label.setText(tr.get("beh_title"))
        self._beh_subtitle_label.setText(tr.get("beh_subtitle"))
        self.behavior_scan_btn.setText(tr.get("analyse_file_btn"))
        self._beh_clear_btn.setText(tr.get("clear_btn"))
        self.behavior_output.setPlaceholderText(tr.get("beh_placeholder"))
        self.behavior_table.setHorizontalHeaderLabels([
            tr.get("col_category"), tr.get("col_indicators"), tr.get("col_top_finding")
        ])
        self.beh_verdict_card.title_label.setText(tr.get("verdict_label"))
        self.beh_score_card.title_label.setText(tr.get("score_label"))
        self.beh_indicators.title_label.setText(tr.get("indicators_label"))

        # Статус в сайдбаре и дашборде
        self.update_dashboard_counts()

    def switch_page(self, index):
        self.stack.setCurrentIndex(index)

        nav_items = _nav_items()
        for i, button in enumerate(self.nav_buttons):
            page_index = nav_items[i][2]
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
        self._dash_title_label = section_title(tr.get("dash_title"))
        self._dash_subtitle_label = section_subtitle(tr.get("dash_subtitle"))
        header_text.addWidget(self._dash_title_label)
        header_text.addWidget(self._dash_subtitle_label)
        header_text_widget.setLayout(header_text)
        header_text_widget.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        header.addWidget(header_text_widget)
        header.addStretch()

        self.status_pill = QLabel(tr.get("dash_protected"))
        self.status_pill.setStyleSheet(f"""
            font-size: 14px; color: {theme.SAFE}; font-weight: 800;
            background-color: rgba(0,255,153,0.12);
            border: 1px solid {theme.SAFE}; border-radius: 18px; padding: 10px 18px;
        """)
        header.addWidget(self.status_pill, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header)

        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(14)
        self.cpu_card = StatCard(tr.get("cpu_usage"), "0%", theme.ACCENT)
        self.ram_card = StatCard(tr.get("ram_usage"), "0%", theme.ACCENT)
        self.threat_card = StatCard(tr.get("threats_blocked"), "0", theme.DANGER)
        self.quarantine_card = StatCard(tr.get("in_quarantine"), "0", theme.WARNING)
        for card in [self.cpu_card, self.ram_card, self.threat_card, self.quarantine_card]:
            stats_layout.addWidget(card)
        layout.addLayout(stats_layout)

        body_layout = QHBoxLayout()
        body_layout.setSpacing(14)

        chart_card = QFrame()
        chart_card.setStyleSheet(theme.CARD_QSS)
        chart_layout = QVBoxLayout()
        chart_layout.setContentsMargins(18, 16, 18, 16)
        self._chart_title_label = QLabel(tr.get("resource_monitor"))
        self._chart_title_label.setStyleSheet(f"color: {theme.TEXT_DIM}; font-size: 11px; font-weight: 700; letter-spacing: 1px; border: none;")
        chart_layout.addWidget(self._chart_title_label)
        self.figure = Figure(figsize=(5, 3))
        self.canvas = FigureCanvas(self.figure)
        chart_layout.addWidget(self.canvas)
        chart_card.setLayout(chart_layout)
        body_layout.addWidget(chart_card, 3)

        process_card = QFrame()
        process_card.setStyleSheet(theme.CARD_QSS)
        process_layout = QVBoxLayout()
        process_layout.setContentsMargins(18, 16, 18, 16)
        self._process_title_label = QLabel(tr.get("top_processes"))
        self._process_title_label.setStyleSheet(f"color: {theme.TEXT_DIM}; font-size: 11px; font-weight: 700; letter-spacing: 1px; border: none;")
        process_layout.addWidget(self._process_title_label)
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
            self.status_pill.setText(tr.get("dash_protected"))
            self.status_pill.setStyleSheet(f"""
                font-size: 14px; color: {theme.SAFE}; font-weight: 800;
                background-color: rgba(0,255,153,0.12);
                border: 1px solid {theme.SAFE}; border-radius: 18px; padding: 10px 18px;
            """)
            self.sidebar_status.setText(tr.get("sidebar_protected"))
            self.sidebar_status.setStyleSheet(f"""
                color: {theme.SAFE}; border: 1px solid {theme.SAFE};
                border-radius: 8px; padding: 8px; font-weight: 700; font-size: 11px;
            """)
        else:
            self.status_pill.setText(tr.get("dash_rt_off"))
            self.status_pill.setStyleSheet(f"""
                font-size: 14px; color: {theme.WARNING}; font-weight: 800;
                background-color: rgba(255,176,32,0.12);
                border: 1px solid {theme.WARNING}; border-radius: 18px; padding: 10px 18px;
            """)
            self.sidebar_status.setText(tr.get("sidebar_monitor_off"))
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

        self._scan_title_label = section_title(tr.get("scan_title"))
        self._scan_subtitle_label = section_subtitle(tr.get("scan_subtitle"))
        layout.addWidget(self._scan_title_label)
        layout.addWidget(self._scan_subtitle_label)

        button_row = QHBoxLayout()
        self.scan_button = QPushButton(tr.get("scan_folder_btn"))
        self.scan_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_button.setStyleSheet(theme.PRIMARY_BUTTON_QSS)
        self.scan_button.clicked.connect(self.scan_directory)
        button_row.addWidget(self.scan_button)

        self.clear_scan_button = QPushButton(tr.get("scan_clear_btn"))
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
        self.output.setPlaceholderText(tr.get("scan_placeholder"))
        layout.addWidget(self.output, 1)
        return page

    def scan_directory(self):
        folder = QFileDialog.getExistingDirectory(self, tr.get("scan_select_folder"))
        if not folder:
            return

        self.scan_button.setEnabled(False)
        self.scan_button.setText(tr.get("scanning"))
        self.scan_progress_label.setText(tr.get("scanning_label") + folder)
        QApplication.processEvents()

        self.output.append(f'<span style="color:{theme.ACCENT}">▶ {tr.get("scanning_label")}{folder}</span>')

        try:
            results = scan_directory(folder)
        except Exception as e:
            self.output.append(f'<span style="color:{theme.DANGER}">Scan failed: {e}</span>')
            results = []

        if not results:
            self.output.append(f'<span style="color:{theme.SAFE}">{tr.get("no_threats")}</span>')
        else:
            for result in results:
                color = theme.risk_color(result["risk"])
                threats_text = ", ".join(result["threats"])
                self.output.append(
                    f'<div style="margin-top:8px;">'
                    f'<span style="color:{color}; font-weight:bold;">{tr.get("threat_detected")} [{result["risk"]}]</span><br>'
                    f'<span style="color:{theme.TEXT}">{tr.get("scan_file_label")}{result["file"]}</span><br>'
                    f'<span style="color:{theme.TEXT_DIM}">{tr.get("scan_reason_label")}{threats_text}</span>'
                    f'</div>'
                )

        self.scan_progress_label.setText(
            f'{tr.get("last_scan")}{folder}  ·  {len(results)} {tr.get("threats_found")}'
        )
        self.scan_button.setEnabled(True)
        self.scan_button.setText(tr.get("scan_folder_btn"))
        self.refresh_all_data()

    # -------------------------------------------------------------- Threats

    def build_threats_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(14)
        page.setLayout(layout)

        self._threats_title_label = section_title(tr.get("threats_title"))
        self._threats_subtitle_label = section_subtitle(tr.get("threats_subtitle"))
        layout.addWidget(self._threats_title_label)
        layout.addWidget(self._threats_subtitle_label)

        filter_row = QHBoxLayout()
        self._filter_label = QLabel(tr.get("filter_by_risk"))
        self._filter_label.setStyleSheet(f"color: {theme.TEXT_DIM}; border: none; font-size: 13px;")
        filter_row.addWidget(self._filter_label)

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
        self.threats_table.setHorizontalHeaderLabels([
            tr.get("col_id"), tr.get("col_file"), tr.get("col_risk"), tr.get("col_date")
        ])
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
            "🛡", tr.get("no_threats_recorded"), tr.get("no_threats_hint")
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
            cursor.execute("SELECT * FROM threats WHERE risk = ? ORDER BY id DESC", (selected,))

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
            risk_item.setForeground(QColor(theme.risk_color(risk)))
            f = risk_item.font(); f.setBold(True); risk_item.setFont(f)
            self.threats_table.setItem(i, 2, risk_item)

            date_item = QTableWidgetItem(str(date))
            date_item.setForeground(QColor(theme.TEXT_DIM))
            self.threats_table.setItem(i, 3, date_item)

        has_rows = len(rows) > 0
        self.threats_table.setVisible(has_rows)
        self.threats_empty.setVisible(not has_rows)

        if not has_rows:
            if selected == "ALL":
                self.threats_empty.set_text("🛡", tr.get("no_threats_recorded"), tr.get("no_threats_hint"))
            else:
                self.threats_empty.set_text(
                    "🛡", tr.get("no_risk_threats").format(selected),
                    tr.get("no_risk_hint").format(selected)
                )
        self.threats_count_label.setText(f"{len(rows)} {tr.get('records')}")

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
        self._quar_title_label = section_title(tr.get("quar_title"))
        self._quar_subtitle_label = section_subtitle(tr.get("quar_subtitle"))
        header_text.addWidget(self._quar_title_label)
        header_text.addWidget(self._quar_subtitle_label)
        header_text_widget.setLayout(header_text)
        header_text_widget.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        header_row.addWidget(header_text_widget)
        header_row.addStretch()

        self._refresh_btn = QPushButton(tr.get("refresh_btn"))
        self._refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._refresh_btn.setStyleSheet(theme.SECONDARY_BUTTON_QSS)
        self._refresh_btn.clicked.connect(self.load_quarantine)
        header_row.addWidget(self._refresh_btn, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header_row)

        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(4)
        self.quarantine_table.setHorizontalHeaderLabels([
            tr.get("col_file"), tr.get("col_size"),
            tr.get("col_quarantined"), tr.get("col_actions")
        ])
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
            "🔒", tr.get("quar_empty_title"), tr.get("quar_empty_hint")
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

            restore_btn = QPushButton(tr.get("restore_btn"))
            restore_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            restore_btn.setStyleSheet(theme.TABLE_ACTION_SAFE_QSS)
            restore_btn.clicked.connect(lambda checked, name=item["name"]: self.handle_restore(name))
            actions_layout.addWidget(restore_btn)

            delete_btn = QPushButton(tr.get("delete_btn"))
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
            self, tr.get("restore_confirm_title"),
            tr.get("restore_confirm_msg").format(filename),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        original_path = os.path.join(QUARANTINE_FOLDER, filename)
        ok = restore_from_quarantine(filename)

        if ok:
            delete_threat_by_file(original_path)
            QMessageBox.information(self, tr.get("restored_title"), tr.get("restored_msg").format(filename))
        else:
            QMessageBox.warning(self, tr.get("restore_fail_title"), tr.get("restore_fail_msg").format(filename))

        self.load_quarantine()
        self.load_threats()
        self.load_logs()

    def handle_delete(self, filename):
        confirm = QMessageBox.question(
            self, tr.get("delete_confirm_title"),
            tr.get("delete_confirm_msg").format(filename),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        ok = delete_from_quarantine(filename)
        if not ok:
            QMessageBox.warning(self, tr.get("delete_fail_title"), tr.get("delete_fail_msg").format(filename))

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
        self._logs_title_label = section_title(tr.get("logs_title"))
        self._logs_subtitle_label = section_subtitle(tr.get("logs_subtitle"))
        header_text.addWidget(self._logs_title_label)
        header_text.addWidget(self._logs_subtitle_label)
        header_text_widget.setLayout(header_text)
        header_text_widget.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        header_row.addWidget(header_text_widget)
        header_row.addStretch()

        self._clear_log_btn = QPushButton(tr.get("clear_log_btn"))
        self._clear_log_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._clear_log_btn.setStyleSheet(theme.DANGER_BUTTON_QSS)
        self._clear_log_btn.clicked.connect(self.handle_clear_logs)
        header_row.addWidget(self._clear_log_btn, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header_row)

        self.log_search = QLineEdit()
        self.log_search.setPlaceholderText(tr.get("search_logs"))
        self.log_search.setStyleSheet(theme.LINE_EDIT_QSS)
        self.log_search.textChanged.connect(self.load_logs)
        layout.addWidget(self.log_search)

        self.logs_output = QTextEdit()
        self.logs_output.setReadOnly(True)
        self.logs_output.setStyleSheet(theme.TEXTEDIT_QSS)
        layout.addWidget(self.logs_output, 1)

        self.logs_empty = EmptyState("📜", tr.get("no_logs_title"), tr.get("no_logs_hint"))
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
                    "🔎", tr.get("no_match_title"),
                    tr.get("no_match_hint").format(self.log_search.text().strip())
                )
            else:
                self.logs_empty.set_text("📜", tr.get("no_logs_title"), tr.get("no_logs_hint"))
            return

        self.logs_output.setVisible(True)
        self.logs_empty.setVisible(False)

        lines = []
        for event in events:
            color = theme.TEXT_DIM
            if "threat" in event.lower() or "blocked" in event.lower() or "error" in event.lower():
                color = theme.DANGER
            elif "quarantine" in event.lower() or "карантин" in event.lower():
                color = theme.WARNING
            elif "restored" in event.lower() or "enabled" in event.lower():
                color = theme.SAFE
            lines.append(f'<span style="color:{color}">{event}</span>')

        self.logs_output.setHtml("<br>".join(lines))

    def handle_clear_logs(self):
        confirm = QMessageBox.question(
            self, tr.get("clear_logs_confirm_title"), tr.get("clear_logs_confirm_msg"),
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

        self._settings_title_label = section_title(tr.get("settings_title"))
        self._settings_subtitle_label = section_subtitle(tr.get("settings_subtitle"))
        layout.addWidget(self._settings_title_label)
        layout.addWidget(self._settings_subtitle_label)

        rt_card = QFrame()
        rt_card.setStyleSheet(theme.CARD_QSS)
        rt_layout = QVBoxLayout()
        rt_layout.setContentsMargins(20, 18, 20, 18)
        rt_layout.setSpacing(10)

        rt_top = QHBoxLayout()
        rt_text = QVBoxLayout()
        rt_text.setSpacing(2)
        self._rt_title_label = QLabel(tr.get("realtime_title"))
        self._rt_title_label.setStyleSheet(f"font-size: 15px; font-weight: 700; color: {theme.TEXT}; border: none;")
        rt_text.addWidget(self._rt_title_label)
        self._rt_desc_label = QLabel(tr.get("realtime_desc"))
        self._rt_desc_label.setStyleSheet(f"font-size: 12px; color: {theme.TEXT_DIM}; border: none;")
        self._rt_desc_label.setWordWrap(True)
        rt_text.addWidget(self._rt_desc_label)
        rt_top.addLayout(rt_text)
        rt_top.addStretch()

        self.realtime_toggle = ToggleSwitch(checked=False)
        self.realtime_toggle.toggled.connect(self.handle_realtime_toggle)
        rt_top.addWidget(self.realtime_toggle, 0, Qt.AlignmentFlag.AlignTop)
        rt_layout.addLayout(rt_top)

        path_row = QHBoxLayout()
        self.realtime_path_label = QLabel(tr.get("watching") + self.realtime_path)
        self.realtime_path_label.setStyleSheet(f"font-size: 12px; color: {theme.ACCENT_DIM}; border: none;")
        path_row.addWidget(self.realtime_path_label, 1)

        self._change_folder_btn = QPushButton(tr.get("change_folder_btn"))
        self._change_folder_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._change_folder_btn.setStyleSheet(theme.SECONDARY_BUTTON_QSS)
        self._change_folder_btn.clicked.connect(self.handle_choose_realtime_path)
        path_row.addWidget(self._change_folder_btn)
        rt_layout.addLayout(path_row)
        rt_card.setLayout(rt_layout)
        layout.addWidget(rt_card)

        about_card = QFrame()
        about_card.setStyleSheet(theme.CARD_QSS)
        about_layout = QVBoxLayout()
        about_layout.setContentsMargins(20, 18, 20, 18)
        about_layout.setSpacing(6)

        self._about_title_label = QLabel(tr.get("about_title"))
        self._about_title_label.setStyleSheet(f"font-size: 15px; font-weight: 700; color: {theme.TEXT}; border: none;")
        about_layout.addWidget(self._about_title_label)

        self._about_text_label = QLabel(tr.get("about_text"))
        self._about_text_label.setWordWrap(True)
        self._about_text_label.setStyleSheet(f"font-size: 12px; color: {theme.TEXT_DIM}; border: none;")
        about_layout.addWidget(self._about_text_label)

        self._version_label = QLabel(tr.get("version_label"))
        self._version_label.setStyleSheet(f"font-size: 11px; color: {theme.TEXT_DIM}; border: none; padding-top: 6px;")
        about_layout.addWidget(self._version_label)

        about_card.setLayout(about_layout)
        layout.addWidget(about_card)
        layout.addStretch()
        return page

    def handle_choose_realtime_path(self):
        folder = QFileDialog.getExistingDirectory(self, tr.get("select_monitor_folder"), self.realtime_path)
        if folder:
            self.realtime_path = folder
            self.realtime_path_label.setText(tr.get("watching") + self.realtime_path)
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
            QMessageBox.warning(self, tr.get("rt_error_title"), str(e))
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
        lines = [tr.get("top_processes"), ""]
        for name, cpu in processes:
            marker = " ⚠" if cpu > 50 else ""
            lines.append(f"{name:<28} {cpu:>5.1f}%{marker}")
        self.process_output.setText("\n".join(lines))

    # ---------------------------------------------------------- Behavior

    def build_behavior_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(14)
        page.setLayout(layout)

        self._beh_title_label = section_title(tr.get("beh_title"))
        self._beh_subtitle_label = section_subtitle(tr.get("beh_subtitle"))
        layout.addWidget(self._beh_title_label)
        layout.addWidget(self._beh_subtitle_label)

        btn_row = QHBoxLayout()
        self.behavior_scan_btn = QPushButton(tr.get("analyse_file_btn"))
        self.behavior_scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.behavior_scan_btn.setStyleSheet(theme.PRIMARY_BUTTON_QSS)
        self.behavior_scan_btn.clicked.connect(self.handle_behavior_scan)
        btn_row.addWidget(self.behavior_scan_btn)

        self._beh_clear_btn = QPushButton(tr.get("clear_btn"))
        self._beh_clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._beh_clear_btn.setStyleSheet(theme.SECONDARY_BUTTON_QSS)
        self._beh_clear_btn.clicked.connect(self._clear_behavior)
        btn_row.addWidget(self._beh_clear_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self.behavior_file_label = QLabel("")
        self.behavior_file_label.setStyleSheet(f"color: {theme.TEXT_DIM}; font-size: 12px; border: none;")
        layout.addWidget(self.behavior_file_label)

        score_row = QHBoxLayout()
        score_row.setSpacing(12)
        self.beh_verdict_card = self._make_beh_stat(tr.get("verdict_label"), "—", theme.TEXT_DIM)
        self.beh_score_card   = self._make_beh_stat(tr.get("score_label"),   "—", theme.ACCENT)
        self.beh_indicators   = self._make_beh_stat(tr.get("indicators_label"), "—", theme.WARNING)
        for card in [self.beh_verdict_card, self.beh_score_card, self.beh_indicators]:
            score_row.addWidget(card)
        layout.addLayout(score_row)

        self.behavior_table = QTableWidget()
        self.behavior_table.setColumnCount(3)
        self.behavior_table.setHorizontalHeaderLabels([
            tr.get("col_category"), tr.get("col_indicators"), tr.get("col_top_finding")
        ])
        self.behavior_table.setStyleSheet(theme.TABLE_QSS)
        self.behavior_table.setAlternatingRowColors(True)
        self.behavior_table.verticalHeader().setVisible(False)
        self.behavior_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.behavior_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.behavior_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.behavior_table.setColumnWidth(0, 180)
        self.behavior_table.setColumnWidth(1, 100)
        layout.addWidget(self.behavior_table)

        self.behavior_output = QTextEdit()
        self.behavior_output.setReadOnly(True)
        self.behavior_output.setStyleSheet(theme.TEXTEDIT_QSS)
        self.behavior_output.setPlaceholderText(tr.get("beh_placeholder"))
        self.behavior_output.setMaximumHeight(180)
        layout.addWidget(self.behavior_output)
        return page

    def _make_beh_stat(self, label, value, color):
        from gui.widgets import StatCard
        card = StatCard(label, value, color)
        return card

    def _clear_behavior(self):
        self.behavior_table.setRowCount(0)
        self.behavior_output.clear()
        self.behavior_file_label.setText("")
        self.beh_verdict_card.set_value("—")
        self.beh_score_card.set_value("—")
        self.beh_indicators.set_value("—")

    def handle_behavior_scan(self):
        path, _ = QFileDialog.getOpenFileName(self, tr.get("select_file_analyse"))
        if not path:
            return

        self.behavior_scan_btn.setEnabled(False)
        self.behavior_scan_btn.setText(tr.get("analysing_btn"))
        QApplication.processEvents()

        result = behavior_analyze(path)
        self.behavior_file_label.setText(tr.get("file_label") + path)

        verdict_colors = {
            "MALICIOUS":  theme.DANGER,
            "SUSPICIOUS": theme.WARNING,
            "CLEAN":      theme.SAFE,
        }
        verdict = result["verdict"]
        color   = verdict_colors.get(verdict, theme.TEXT_DIM)

        self.beh_verdict_card.value_label.setText(verdict)
        self.beh_verdict_card.value_label.setStyleSheet(
            f"color: {color}; font-size: 22px; font-weight: 800; border: none;"
        )
        self.beh_score_card.set_value(f"{result['score']}/100")
        self.beh_indicators.set_value(str(result["total_indicators"]))

        self.behavior_table.setRowCount(0)
        for cat_key, findings in result["categories"].items():
            if not findings:
                continue
            row = self.behavior_table.rowCount()
            self.behavior_table.insertRow(row)

            cat_item = QTableWidgetItem(CATEGORY_NAMES[cat_key])
            self.behavior_table.setItem(row, 0, cat_item)

            count_item = QTableWidgetItem(str(len(findings)))
            worst = max(findings, key=lambda x: x["severity_int"])
            count_color = QColor(
                theme.DANGER  if worst["severity"] == "HIGH"   else
                theme.WARNING if worst["severity"] == "MEDIUM" else
                theme.TEXT_DIM
            )
            count_item.setForeground(count_color)
            f = count_item.font(); f.setBold(True); count_item.setFont(f)
            self.behavior_table.setItem(row, 1, count_item)

            top_item = QTableWidgetItem(worst["description"])
            top_item.setForeground(QColor(theme.TEXT_DIM))
            self.behavior_table.setItem(row, 2, top_item)

        from core.behevior_monitor import format_report
        self.behavior_output.setPlainText(format_report(result))

        self.behavior_scan_btn.setEnabled(True)
        self.behavior_scan_btn.setText(tr.get("analyse_file_btn"))

        from core.logger import log_event
        log_event(f"Behavior analysis: {os.path.basename(path)} — {verdict} (score {result['score']}/100)")

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

        self._ai_title_label = section_title(tr.get("ai_title"))
        self._ai_subtitle_label = section_subtitle(tr.get("ai_subtitle"))
        layout.addWidget(self._ai_title_label)
        layout.addWidget(self._ai_subtitle_label)

        self.ai_status_card = QFrame()
        self.ai_status_card.setStyleSheet(theme.CARD_QSS)
        status_layout = QHBoxLayout()
        status_layout.setContentsMargins(20, 16, 20, 16)

        self.ai_status_icon = QLabel("🤖")
        self.ai_status_icon.setStyleSheet("font-size: 28px; border: none;")
        status_layout.addWidget(self.ai_status_icon)

        status_text = QVBoxLayout()
        status_text.setSpacing(2)
        self.ai_status_title = QLabel()
        self.ai_status_title.setStyleSheet(f"font-size: 15px; font-weight: 700; color: {theme.TEXT}; border: none;")
        self.ai_status_desc = QLabel()
        self.ai_status_desc.setStyleSheet(f"font-size: 12px; color: {theme.TEXT_DIM}; border: none;")
        status_text.addWidget(self.ai_status_title)
        status_text.addWidget(self.ai_status_desc)
        status_layout.addLayout(status_text, 1)

        self.ai_train_button = QPushButton(tr.get("train_btn"))
        self.ai_train_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ai_train_button.setStyleSheet(theme.PRIMARY_BUTTON_QSS)
        self.ai_train_button.clicked.connect(self.handle_train_model)
        status_layout.addWidget(self.ai_train_button, 0, Qt.AlignmentFlag.AlignRight)
        self.ai_status_card.setLayout(status_layout)
        layout.addWidget(self.ai_status_card)

        btn_row = QHBoxLayout()
        self.ai_scan_file_btn = QPushButton(tr.get("scan_file_btn"))
        self.ai_scan_file_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ai_scan_file_btn.setStyleSheet(theme.PRIMARY_BUTTON_QSS)
        self.ai_scan_file_btn.clicked.connect(self.handle_ai_scan_file)
        btn_row.addWidget(self.ai_scan_file_btn)

        self.ai_scan_folder_btn = QPushButton(tr.get("scan_folder_btn_ai"))
        self.ai_scan_folder_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ai_scan_folder_btn.setStyleSheet(theme.SECONDARY_BUTTON_QSS)
        self.ai_scan_folder_btn.clicked.connect(self.handle_ai_scan_folder)
        btn_row.addWidget(self.ai_scan_folder_btn)

        self._ai_clear_btn = QPushButton(tr.get("clear_btn"))
        self._ai_clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._ai_clear_btn.setStyleSheet(theme.SECONDARY_BUTTON_QSS)
        self._ai_clear_btn.clicked.connect(lambda: (
            self.ai_results_table.setRowCount(0),
            self.ai_summary_label.setText("")
        ))
        btn_row.addWidget(self._ai_clear_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self._refresh_ai_status()

        self.ai_summary_label = QLabel("")
        self.ai_summary_label.setStyleSheet(f"color: {theme.TEXT_DIM}; font-size: 12px; border: none;")
        layout.addWidget(self.ai_summary_label)

        self.ai_results_table = QTableWidget()
        self.ai_results_table.setColumnCount(5)
        self.ai_results_table.setHorizontalHeaderLabels([
            tr.get("col_file"), tr.get("col_ai_label"),
            tr.get("col_confidence"), tr.get("col_risk"), tr.get("col_top_signal")
        ])
        self.ai_results_table.setStyleSheet(theme.TABLE_QSS)
        self.ai_results_table.setAlternatingRowColors(True)
        self.ai_results_table.verticalHeader().setVisible(False)
        self.ai_results_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.ai_results_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.ai_results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.ai_results_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.ai_results_table.setColumnWidth(1, 100)
        self.ai_results_table.setColumnWidth(2, 110)
        self.ai_results_table.setColumnWidth(3, 80)
        layout.addWidget(self.ai_results_table, 1)
        return page

    def _refresh_ai_status(self):
        ready = is_model_ready()
        if ready:
            self.ai_status_title.setText(tr.get("model_ready"))
            self.ai_status_title.setStyleSheet(
                f"font-size: 15px; font-weight: 700; color: {theme.SAFE}; border: none;"
            )
            from ai.model import get_model_info
            self.ai_status_desc.setText(get_model_info() + " · model.pkl loaded from ai/")
            self.ai_train_button.setText(tr.get("retrain_btn"))
            self.ai_scan_file_btn.setEnabled(True)
            self.ai_scan_folder_btn.setEnabled(True)
        else:
            self.ai_status_title.setText(tr.get("model_not_trained"))
            self.ai_status_title.setStyleSheet(
                f"font-size: 15px; font-weight: 700; color: {theme.WARNING}; border: none;"
            )
            self.ai_status_desc.setText(tr.get("model_not_trained_desc"))
            self.ai_train_button.setText(tr.get("train_btn"))
            self.ai_scan_file_btn.setEnabled(False)
            self.ai_scan_folder_btn.setEnabled(False)

    def handle_train_model(self):
        self.ai_train_button.setEnabled(False)
        self.ai_train_button.setText(tr.get("training_btn"))
        self.ai_status_desc.setText(tr.get("training_desc"))
        QApplication.processEvents()

        import threading

        def _train():
            try:
                train_model(n_malware=400, n_safe=400)
            except Exception as e:
                from core.logger import log_event
                log_event(f"AI training error: {e}")
            finally:
                QTimer.singleShot(0, self._on_training_done)

        threading.Thread(target=_train, daemon=True).start()

    def _on_training_done(self):
        import ai.model as _m
        _m._model  = None
        _m._scaler = None
        self.ai_train_button.setEnabled(True)
        self._refresh_ai_status()
        from core.logger import log_event
        log_event("AI model trained successfully")
        self.load_logs()

    def _ai_top_signal(self, features: dict) -> str:
        checks = [
            (features.get("keyword_count", 0) >= 3,       tr.get("top_signal_keywords").format(int(features['keyword_count']))),
            (features.get("base64_score", 0) >= 0.4,      tr.get("top_signal_base64")),
            (features.get("url_count", 0) >= 1,           tr.get("top_signal_urls").format(int(features['url_count']))),
            (features.get("entropy", 0) >= 6.5,           tr.get("top_signal_entropy").format(f"{features['entropy']:.1f}")),
            (features.get("ip_count", 0) >= 1,            tr.get("top_signal_ip").format(int(features['ip_count']))),
            (features.get("suspicious_ext", 0) == 1.0,    tr.get("top_signal_ext")),
            (features.get("non_ascii_ratio", 0) >= 0.3,   tr.get("top_signal_nonascii")),
            (features.get("unique_line_ratio", 0) <= 0.3, tr.get("top_signal_lines")),
        ]
        signals = [desc for cond, desc in checks if cond]
        return ", ".join(signals[:3]) if signals else tr.get("top_signal_general")

    def _add_ai_result_row(self, file_path: str, result: dict):
        row = self.ai_results_table.rowCount()
        self.ai_results_table.insertRow(row)

        name_item = QTableWidgetItem(os.path.basename(file_path))
        name_item.setToolTip(file_path)
        self.ai_results_table.setItem(row, 0, name_item)

        label = result["label"]
        label_color = theme.DANGER if label == "MALWARE" else theme.SAFE
        label_item = QTableWidgetItem(label)
        label_item.setForeground(QColor(label_color))
        f = label_item.font(); f.setBold(True); label_item.setFont(f)
        self.ai_results_table.setItem(row, 1, label_item)

        conf_item = QTableWidgetItem(f"{result['confidence']:.0%}")
        conf_item.setForeground(QColor(theme.TEXT_DIM))
        self.ai_results_table.setItem(row, 2, conf_item)

        risk = result["risk"]
        risk_item = QTableWidgetItem(risk)
        risk_item.setForeground(QColor(theme.risk_color(risk)))
        f = risk_item.font(); f.setBold(True); risk_item.setFont(f)
        self.ai_results_table.setItem(row, 3, risk_item)

        signal_item = QTableWidgetItem(self._ai_top_signal(result["features"]))
        signal_item.setForeground(QColor(theme.TEXT_DIM))
        self.ai_results_table.setItem(row, 4, signal_item)

    def handle_ai_scan_file(self):
        path, _ = QFileDialog.getOpenFileName(self, tr.get("select_file_scan"))
        if not path:
            return

        result = predict_file(path)
        if result is None:
            QMessageBox.warning(self, tr.get("scan_fail_title"), tr.get("scan_fail_msg").format(path))
            return

        self._add_ai_result_row(path, result)
        self.ai_summary_label.setText(
            tr.get("last_scan_ai").format(
                os.path.basename(path), result['label'], f"{result['confidence']:.0%}"
            )
        )

    def handle_ai_scan_folder(self):
        folder = QFileDialog.getExistingDirectory(self, tr.get("select_folder_scan"))
        if not folder:
            return

        self.ai_scan_folder_btn.setEnabled(False)
        self.ai_scan_folder_btn.setText(tr.get("scanning"))
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
                self.ai_scan_folder_btn.setText(tr.get("scanning_progress").format(i+1, len(files)))
                QApplication.processEvents()

        self.ai_summary_label.setText(
            tr.get("scanned_summary").format(len(files), malware_count, len(files) - malware_count)
        )
        self.ai_scan_folder_btn.setEnabled(True)
        self.ai_scan_folder_btn.setText(tr.get("scan_folder_btn_ai"))


def run_gui():
    app = QApplication(sys.argv)
    window = AntivirusGUI()
    window.show()
    sys.exit(app.exec())
