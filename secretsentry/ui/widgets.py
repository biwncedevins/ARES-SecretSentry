"""Shared, reusable UI building blocks."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from .theme import COLORS, confidence_color, severity_color

FRAME_STYLES = {
    "card": "card",
    "accent": "cardAccent",
    "soft": "cardSoft",
}


def card(style: str = "card") -> QFrame:
    """Create a styled card frame and return it (caller adds a layout)."""
    frame = QFrame()
    frame.setObjectName(FRAME_STYLES[style])
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(20, 20, 20, 20)
    layout.setSpacing(12)
    return frame


def vbox(parent: QWidget | None = None, *, margins: int = 20, spacing: int = 12) -> QVBoxLayout:
    layout = QVBoxLayout(parent)
    layout.setContentsMargins(margins, margins, margins, margins)
    layout.setSpacing(spacing)
    return layout


def hbox(parent: QWidget | None = None, *, margins: int = 0, spacing: int = 10) -> QHBoxLayout:
    layout = QHBoxLayout(parent)
    layout.setContentsMargins(margins, margins, margins, margins)
    layout.setSpacing(spacing)
    return layout


def label(text: str = "", *, style: str = "", object_name: str = "") -> QLabel:
    lbl = QLabel(text)
    if style:
        lbl.setStyleSheet(style)
    if object_name:
        lbl.setObjectName(object_name)
    lbl.setWordWrap(True)
    lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return lbl


def title(text: str) -> QLabel:
    return label(text, object_name="pageTitle")


def subtitle(text: str) -> QLabel:
    return label(text, object_name="pageSubtitle")


def section(text: str) -> QLabel:
    return label(text, object_name="sectionTitle")


def muted(text: str) -> QLabel:
    return label(text, object_name="muted")


def hint(text: str) -> QLabel:
    return label(text, object_name="hint")


def badge(text: str, *, color: str, soft: str, icon: str = "") -> QLabel:
    chip = QLabel((icon + "  " + text) if icon else text)
    chip.setStyleSheet(
        f"""
        QLabel {{
            background: {soft};
            color: {color};
            border: 1px solid {COLORS['card_border']};
            border-radius: 100px;
            padding: 3px 12px;
            font-weight: 700;
            font-size: 11px;
        }}
        """
    )
    chip.setAlignment(Qt.AlignCenter)
    chip.setWordWrap(False)
    chip.setTextInteractionFlags(Qt.NoTextInteraction)
    return chip


def severity_badge(severity: str) -> QLabel:
    color = severity_color(severity)
    soft = {
        "critical": COLORS["critical_soft"],
        "high": COLORS["high_soft"],
        "medium": COLORS["medium_soft"],
        "low": COLORS["low_soft"],
        "info": COLORS["info_soft"],
    }[severity]
    return badge(severity.upper(), color=color, soft=soft)


def confidence_badge(confidence: str) -> QLabel:
    return badge(confidence.upper(), color=confidence_color(confidence), soft=COLORS["bg_soft"])


def stat_value(value: str, *, color: str | None = None) -> QLabel:
    lbl = label(value, style=(
        f"font-size: 26px; font-weight: 800; "
        f"color: {color or COLORS['text']};"
    ))
    lbl.setWordWrap(False)
    lbl.setTextInteractionFlags(Qt.NoTextInteraction)
    return lbl


def stat_label(text: str) -> QLabel:
    lbl = muted(text)
    lbl.setTextInteractionFlags(Qt.NoTextInteraction)
    lbl.setWordWrap(False)
    return lbl


def vspacer() -> QWidget:
    sp = QWidget()
    sp.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
    return sp


def hspacer() -> QWidget:
    sp = QWidget()
    sp.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
    return sp


def divider() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.HLine)
    line.setStyleSheet(f"color: {COLORS['card_border']}; background: {COLORS['card_border']};")
    line.setFixedHeight(1)
    return line