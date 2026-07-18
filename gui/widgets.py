"""
Small reusable widgets shared across screens.
"""

from PyQt6.QtWidgets import QFrame, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QGraphicsOpacityEffect
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QFont

from gui import theme


class StatCard(QFrame):
    """A small metric card: label on top, big value below, optional accent color."""

    def __init__(self, title, value="—", accent=theme.ACCENT, subtitle=""):
        super().__init__()
        self.setStyleSheet(theme.CARD_QSS)
        self.setMinimumHeight(110)

        layout = QVBoxLayout()
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(4)

        title_label = QLabel(title.upper())
        title_label.setStyleSheet(f"color: {theme.TEXT_DIM}; font-size: 11px; font-weight: 700; letter-spacing: 1px; border: none;")
        layout.addWidget(title_label)

        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"color: {accent}; font-size: 28px; font-weight: 800; border: none;")
        layout.addWidget(self.value_label)

        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setStyleSheet(f"color: {theme.TEXT_DIM}; font-size: 11px; border: none;")
        self.subtitle_label.setVisible(bool(subtitle))
        layout.addWidget(self.subtitle_label)

        layout.addStretch()
        self.setLayout(layout)

    def set_value(self, value):
        self.value_label.setText(str(value))

    def set_subtitle(self, text):
        self.subtitle_label.setText(text)
        self.subtitle_label.setVisible(bool(text))


class RiskBadge(QLabel):
    """A small rounded pill showing HIGH/MEDIUM/LOW with the matching color."""

    def __init__(self, risk):
        super().__init__(risk)
        color = theme.risk_color(risk)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(f"""
            background-color: {color}33;
            color: {color};
            border: 1px solid {color};
            border-radius: 9px;
            font-weight: 700;
            font-size: 11px;
            padding: 3px 10px;
        """)


class ToggleSwitch(QPushButton):
    """A simple ON/OFF toggle styled as a pill button (no native QSS toggle in Qt)."""

    def __init__(self, checked=False):
        super().__init__()
        self.setCheckable(True)
        self.setChecked(checked)
        self.setFixedSize(70, 32)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._refresh()
        self.toggled.connect(self._refresh)

    def _refresh(self):
        if self.isChecked():
            self.setText("ON")
            self.setStyleSheet(theme.TOGGLE_QSS_ON)
        else:
            self.setText("OFF")
            self.setStyleSheet(theme.TOGGLE_QSS_OFF)


class EmptyState(QFrame):
    """Shown instead of an empty table/list — explains the state and what to do next."""

    def __init__(self, icon, title, subtitle):
        super().__init__()
        self.setStyleSheet(f"background-color: transparent; border: none;")

        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(6)

        self.icon_label = QLabel(icon)
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_label.setStyleSheet(f"font-size: 40px; border: none; color: {theme.TEXT_DIM};")
        layout.addWidget(self.icon_label)

        self.title_label = QLabel(title)
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setStyleSheet(f"font-size: 16px; font-weight: 700; color: {theme.TEXT}; border: none;")
        layout.addWidget(self.title_label)

        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.subtitle_label.setWordWrap(True)
        self.subtitle_label.setStyleSheet(f"font-size: 12px; color: {theme.TEXT_DIM}; border: none;")
        layout.addWidget(self.subtitle_label)

        self.setLayout(layout)

    def set_text(self, icon, title, subtitle):
        self.icon_label.setText(icon)
        self.title_label.setText(title)
        self.subtitle_label.setText(subtitle)


def apply_fade_in(widget, duration=220):
    """Applies a quick fade-in animation when a page becomes visible."""
    effect = QGraphicsOpacityEffect(widget)
    widget.setGraphicsEffect(effect)

    animation = QPropertyAnimation(effect, b"opacity")
    animation.setDuration(duration)
    animation.setStartValue(0.0)
    animation.setEndValue(1.0)
    animation.setEasingCurve(QEasingCurve.Type.OutCubic)
    animation.start()

    # keep a reference so it isn't garbage-collected mid-animation
    widget._fade_animation = animation


def section_title(text):
    label = QLabel(text)
    label.setStyleSheet(f"font-size: 22px; font-weight: 800; color: {theme.TEXT}; border: none; padding: 4px 0px;")
    return label


def section_subtitle(text):
    label = QLabel(text)
    label.setStyleSheet(f"font-size: 13px; color: {theme.TEXT_DIM}; border: none; padding-bottom: 8px;")
    label.setWordWrap(True)
    return label
