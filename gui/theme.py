"""
Central theme for SentinelX. One palette, one place to change it.
Keeping every color/spacing constant here means every screen stays visually consistent
instead of each widget inventing its own hex codes.
"""

# ---- Palette ---------------------------------------------------------------
BG = "#0A0F1C"            # app background
PANEL = "#111827"         # card / sidebar / table background
PANEL_ALT = "#161F32"     # slightly lighter panel, for hover/zebra rows
BORDER = "#1F2A3D"        # quiet hairline border
ACCENT = "#00F5FF"        # cyan — brand / focus / primary actions
ACCENT_DIM = "#0B8C94"    # muted cyan for secondary text
DANGER = "#FF3B3B"        # HIGH risk / destructive actions
WARNING = "#FFB020"       # MEDIUM risk
SAFE = "#00FF99"          # LOW risk / protected status
TEXT = "#E6F1FF"          # primary text (off-white, cool tint)
TEXT_DIM = "#7C8AA5"      # secondary / muted text

FONT_FAMILY = "Segoe UI, Arial"
MONO_FAMILY = "Consolas, 'Courier New', monospace"

RADIUS = 10


def risk_color(risk: str) -> str:
    return {
        "HIGH": DANGER,
        "MEDIUM": WARNING,
        "LOW": SAFE,
    }.get(risk, TEXT_DIM)


# ---- Global stylesheet ------------------------------------------------------
GLOBAL_QSS = f"""
QWidget {{
    background-color: {BG};
    color: {TEXT};
    font-family: {FONT_FAMILY};
    font-size: 14px;
}}

QToolTip {{
    background-color: {PANEL_ALT};
    color: {TEXT};
    border: 1px solid {ACCENT};
    padding: 6px;
    border-radius: 6px;
}}

QScrollBar:vertical {{
    background: {BG};
    width: 10px;
    margin: 0px;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 5px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{
    background: {ACCENT_DIM};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background: {BG};
    height: 10px;
}}
QScrollBar::handle:horizontal {{
    background: {BORDER};
    border-radius: 5px;
    min-width: 24px;
}}
"""

SIDEBAR_QSS = f"""
QFrame#Sidebar {{
    background-color: {PANEL};
    border-right: 1px solid {BORDER};
}}
"""

NAV_BUTTON_QSS = f"""
QPushButton {{
    background-color: transparent;
    color: {TEXT_DIM};
    text-align: left;
    padding: 12px 16px;
    border-radius: {RADIUS}px;
    font-size: 14px;
    font-weight: 600;
    border: 1px solid transparent;
}}
QPushButton:hover {{
    background-color: {PANEL_ALT};
    color: {TEXT};
}}
"""

NAV_BUTTON_ACTIVE_QSS = f"""
QPushButton {{
    background-color: rgba(0, 245, 255, 0.12);
    color: {ACCENT};
    text-align: left;
    padding: 12px 16px;
    border-radius: {RADIUS}px;
    font-size: 14px;
    font-weight: 700;
    border: 1px solid {ACCENT};
}}
"""

PRIMARY_BUTTON_QSS = f"""
QPushButton {{
    background-color: {ACCENT};
    color: #00131A;
    padding: 13px;
    border-radius: {RADIUS}px;
    font-size: 15px;
    font-weight: 700;
    border: none;
}}
QPushButton:hover {{
    background-color: #5CFBFF;
}}
QPushButton:pressed {{
    background-color: #00C4CC;
}}
QPushButton:disabled {{
    background-color: {BORDER};
    color: {TEXT_DIM};
}}
"""

SECONDARY_BUTTON_QSS = f"""
QPushButton {{
    background-color: {PANEL_ALT};
    color: {TEXT};
    padding: 10px 16px;
    border-radius: {RADIUS}px;
    font-size: 13px;
    font-weight: 600;
    border: 1px solid {BORDER};
}}
QPushButton:hover {{
    border: 1px solid {ACCENT};
    color: {ACCENT};
}}
"""

DANGER_BUTTON_QSS = f"""
QPushButton {{
    background-color: transparent;
    color: {DANGER};
    padding: 8px 14px;
    border-radius: 8px;
    font-size: 12px;
    font-weight: 700;
    border: 1px solid {DANGER};
}}
QPushButton:hover {{
    background-color: rgba(255, 59, 59, 0.15);
}}
"""

SAFE_BUTTON_QSS = f"""
QPushButton {{
    background-color: transparent;
    color: {SAFE};
    padding: 8px 14px;
    border-radius: 8px;
    font-size: 12px;
    font-weight: 700;
    border: 1px solid {SAFE};
}}
QPushButton:hover {{
    background-color: rgba(0, 255, 153, 0.15);
}}
"""

TABLE_ACTION_DANGER_QSS = f"""
QPushButton {{
    background-color: transparent;
    color: {DANGER};
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    border: 1px solid {DANGER};
    min-width: 50px;
}}
QPushButton:hover {{
    background-color: rgba(255, 59, 59, 0.15);
}}
"""

TABLE_ACTION_SAFE_QSS = f"""
QPushButton {{
    background-color: transparent;
    color: {SAFE};
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    border: 1px solid {SAFE};
    min-width: 50px;
}}
QPushButton:hover {{
    background-color: rgba(0, 255, 153, 0.15);
}}
"""

CARD_QSS = f"""
QFrame {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 14px;
}}
"""

TABLE_QSS = f"""
QTableWidget {{
    background-color: {PANEL};
    alternate-background-color: {PANEL_ALT};
    color: {TEXT};
    gridline-color: {BORDER};
    border: 1px solid {BORDER};
    border-radius: 10px;
    font-size: 13px;
    selection-background-color: rgba(0, 245, 255, 0.18);
    selection-color: {TEXT};
}}
QHeaderView::section {{
    background-color: {PANEL_ALT};
    color: {ACCENT};
    padding: 10px;
    border: none;
    border-bottom: 2px solid {BORDER};
    font-weight: 700;
    font-size: 12px;
}}
QTableWidget::item {{
    padding: 6px;
    border-bottom: 1px solid {BORDER};
}}
"""

COMBO_QSS = f"""
QComboBox {{
    background-color: {PANEL_ALT};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 13px;
}}
QComboBox:hover {{
    border: 1px solid {ACCENT};
}}
QComboBox::drop-down {{
    border: none;
    width: 24px;
}}
QComboBox QAbstractItemView {{
    background-color: {PANEL_ALT};
    color: {TEXT};
    selection-background-color: {ACCENT};
    selection-color: #00131A;
    border: 1px solid {ACCENT};
    outline: none;
}}
"""

LINE_EDIT_QSS = f"""
QLineEdit {{
    background-color: {PANEL_ALT};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 9px 12px;
    font-size: 13px;
}}
QLineEdit:focus {{
    border: 1px solid {ACCENT};
}}
"""

TEXTEDIT_QSS = f"""
QTextEdit {{
    background-color: {PANEL};
    color: {ACCENT};
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 10px;
    font-family: {MONO_FAMILY};
    font-size: 12px;
}}
"""

TOGGLE_QSS_ON = f"""
QPushButton {{
    background-color: {SAFE};
    color: #00130D;
    border-radius: 16px;
    font-weight: 700;
    font-size: 12px;
    border: none;
}}
"""

TOGGLE_QSS_OFF = f"""
QPushButton {{
    background-color: {BORDER};
    color: {TEXT_DIM};
    border-radius: 16px;
    font-weight: 700;
    font-size: 12px;
    border: none;
}}
"""
