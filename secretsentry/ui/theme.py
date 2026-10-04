"""Theme constants and the global QSS stylesheet.

Design language: clean professional developer tool.
White surfaces, dark gray/black type, yellow accent used selectively,
restrained borders, soft shadows, no "hacker" aesthetic.
"""

from __future__ import annotations

# Design system ---------------------------------------------------------------
COLORS = {
    "bg": "#FFFFFF",
    "bg_soft": "#F7F7F5",          # very light warm gray for wells
    "bg_hover": "#FAFAFA",
    "card_border": "#E7E5E4",
    "border_strong": "#D6D3D1",
    "text": "#1C1917",             # near-black, warm
    "text_secondary": "#57534E",
    "text_muted": "#A8A29E",
    "accent": "#FACC15",           # primary yellow
    "accent_hover": "#EAB308",
    "accent_soft": "#FEF9C3",      # pale yellow tint
    "accent_text": "#1F2937",      # dark text on yellow
    "selection_bg": "#FEF9C3",
    "critical": "#DC2626",
    "critical_soft": "#FEF2F2",
    "high": "#EA580C",
    "high_soft": "#FFF7ED",
    "medium": "#B45309",
    "medium_soft": "#FFFBEB",
    "low": "#6B7280",
    "low_soft": "#F3F4F6",
    "info": "#3B82F6",
    "info_soft": "#EFF6FF",
    "code_bg": "#1C1917",
    "code_text": "#E7E5E4",
    "code_accent": "#FDE68A",
}


def severity_color(severity: str) -> str:
    return {
        "critical": COLORS["critical"],
        "high": COLORS["high"],
        "medium": COLORS["medium"],
        "low": COLORS["low"],
        "info": COLORS["info"],
    }[severity]


def confidence_color(confidence: str) -> str:
    return {
        "high": COLORS["critical"],
        "medium": COLORS["medium"],
        "low": COLORS["low"],
    }[confidence]


# ---------------------------------------------------------------------------
QSS = f"""
QWidget {{
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
    color: {COLORS['text']};
    background: transparent;
}}
QMainWindow, QDialog {{
    background: {COLORS['bg']};
}}

/* ---- Typography ------------------------------------------------------- */
QLabel#pageTitle {{
    font-size: 22px;
    font-weight: 700;
    color: {COLORS['text']};
}}
QLabel#pageSubtitle {{
    font-size: 13px;
    color: {COLORS['text_secondary']};
}}
QLabel#sectionTitle {{
    font-size: 15px;
    font-weight: 600;
    color: {COLORS['text']};
}}
QLabel#muted {{
    color: {COLORS['text_muted']};
}}
QLabel#hint {{
    color: {COLORS['text_secondary']};
    background: {COLORS['bg_soft']};
    border: 1px solid {COLORS['card_border']};
    border-radius: 8px;
    padding: 10px 14px;
}}

/* ---- Cards ------------------------------------------------------------ */
QFrame#card {{
    background: {COLORS['bg']};
    border: 1px solid {COLORS['card_border']};
    border-radius: 12px;
}}
QFrame#cardAccent {{
    background: {COLORS['bg']};
    border: 1px solid {COLORS['accent']};
    border-radius: 12px;
}}
QFrame#cardSoft {{
    background: {COLORS['bg_soft']};
    border: 1px solid {COLORS['card_border']};
    border-radius: 12px;
}}

/* ---- Code / preview boxes --------------------------------------------- */
QFrame#codeBox {{
    background: {COLORS['code_bg']};
    border: none;
    border-radius: 10px;
}}
QLabel#codeText {{
    background: {COLORS['code_bg']};
    color: {COLORS['code_text']};
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 12px;
    padding: 12px 14px;
}}
QLabel#codeAccent {{
    background: {COLORS['code_bg']};
    color: {COLORS['code_accent']};
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 12px;
    padding: 12px 14px;
}}

/* ---- Form controls ------------------------------------------------------ */
QLineEdit, QComboBox {{
    background: {COLORS['bg']};
    border: 1px solid {COLORS['border_strong']};
    border-radius: 8px;
    padding: 7px 12px;
    min-height: 20px;
    selection-background-color: {COLORS['accent']};
    selection-color: {COLORS['accent_text']};
}}
QLineEdit:focus, QComboBox:focus {{
    border: 1px solid {COLORS['accent']};
}}
QLineEdit:disabled {{
    background: {COLORS['bg_soft']};
    color: {COLORS['text_secondary']};
}}
QComboBox::drop-down {{
    border: none;
    width: 26px;
}}
QComboBox::down-arrow {{
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid {COLORS['text_secondary']};
    margin-right: 8px;
}}
QComboBox QAbstractItemView {{
    background: {COLORS['bg']};
    border: 1px solid {COLORS['card_border']};
    border-radius: 8px;
    selection-background-color: {COLORS['selection_bg']};
    selection-color: {COLORS['text']};
    outline: none;
}}

/* ---- Buttons ------------------------------------------------------------ */
QPushButton {{
    background: {COLORS['bg']};
    color: {COLORS['text']};
    border: 1px solid {COLORS['border_strong']};
    border-radius: 8px;
    padding: 8px 18px;
    min-height: 20px;
    font-weight: 600;
}}
QPushButton:hover {{
    background: {COLORS['bg_hover']};
    border-color: {COLORS['text_muted']};
}}
QPushButton:pressed {{
    background: {COLORS['bg_soft']};
}}
QPushButton:disabled {{
    color: {COLORS['text_muted']};
    background: {COLORS['bg_soft']};
    border-color: {COLORS['card_border']};
}}

QPushButton[role="primary"] {{
    background: {COLORS['accent']};
    color: {COLORS['accent_text']};
    border: 1px solid {COLORS['accent_hover']};
}}
QPushButton[role="primary"]:hover {{
    background: {COLORS['accent_hover']};
    border-color: {COLORS['accent_hover']};
}}
QPushButton[role="primary"]:pressed {{
    background: #CA8A04;
    border-color: #CA8A04;
}}
QPushButton[role="primary"]:disabled {{
    background: #F3E8A1;
    border-color: #F3E8A1;
    color: #7A6E3A;
}}

QPushButton[role="ghost"] {{
    background: transparent;
    border: none;
    color: {COLORS['text_secondary']};
    padding: 7px 12px;
    font-weight: 500;
}}
QPushButton[role="ghost"]:hover {{
    background: {COLORS['bg_soft']};
    color: {COLORS['text']};
}}

/* Nav buttons in the sidebar. */
QPushButton[role="nav"] {{
    background: transparent;
    border: none;
    border-radius: 0px;
    border-left: 3px solid transparent;
    color: {COLORS['text_secondary']};
    text-align: left;
    padding: 10px 18px;
    font-weight: 500;
    font-size: 13px;
}}
QPushButton[role="nav"]:hover {{
    background: {COLORS['bg_soft']};
    color: {COLORS['text']};
}}
QPushButton[role="nav"]:checked {{
    background: {COLORS['accent_soft']};
    color: {COLORS['text']};
    border-left: 3px solid {COLORS['accent']};
    font-weight: 700;
}}

/* ---- Table -------------------------------------------------------------- */
QTableView {{
    background: {COLORS['bg']};
    alternate-background-color: #FCFCFB;
    border: 1px solid {COLORS['card_border']};
    border-radius: 10px;
    gridline-color: transparent;
    selection-background-color: {COLORS['selection_bg']};
    selection-color: {COLORS['text']};
    outline: none;
}}
QTableView::item {{
    padding: 4px 6px;
    border-bottom: 1px solid #F5F5F4;
}}
QTableView::item:selected {{
    background: {COLORS['selection_bg']};
    color: {COLORS['text']};
}}
QHeaderView::section {{
    background: #FAFAF9;
    color: {COLORS['text_muted']};
    border: none;
    border-bottom: 1px solid {COLORS['card_border']};
    padding: 9px 8px;
    font-weight: 600;
    font-size: 12px;
}}
QTableCornerButton::section {{
    background: #FAFAF9;
    border: none;
}}

/* ---- Scrollbars ----------------------------------------------------------- */
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 2px;
}}
QScrollBar::handle:vertical {{
    background: #D6D3D1;
    border-radius: 4px;
    min-height: 28px;
}}
QScrollBar::handle:vertical:hover {{
    background: {COLORS['text_muted']};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
    margin: 2px;
}}
QScrollBar::handle:horizontal {{
    background: #D6D3D1;
    border-radius: 4px;
    min-width: 28px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

/* ---- Progress -------------------------------------------------------------- */
QProgressBar {{
    background: {COLORS['bg_soft']};
    border: 1px solid {COLORS['card_border']};
    border-radius: 6px;
    height: 10px;
    text-align: center;
}}
QProgressBar::chunk {{
    background: {COLORS['accent']};
    border-radius: 5px;
}}

/* ---- Splitter / toolbars ---------------------------------------------------- */
QSplitter::handle {{
    background: {COLORS['card_border']};
}}
QToolBar {{
    background: {COLORS['bg']};
    border: none;
    border-bottom: 1px solid {COLORS['card_border']};
    spacing: 8px;
    padding: 6px;
}}
QToolButton {{
    background: transparent;
    border: none;
    padding: 5px 8px;
    color: {COLORS['text_secondary']};
}}
QToolButton:hover {{
    background: {COLORS['bg_soft']};
}}
"""


def apply_theme(app) -> None:
    """Install the global stylesheet on a QApplication."""
    app.setStyleSheet(QSS)
    font = app.font()
    font.setFamilies(["Segoe UI", "Inter"])
    font.setPointSize(10)
    app.setFont(font)