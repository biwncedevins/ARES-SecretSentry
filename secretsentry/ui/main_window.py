"""Application shell: sidebar navigation + stacked pages."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .. import __version__, APP_NAME
from ..models import ScanResult
from .dashboard import DashboardPage
from .report_page import ReportPage
from .results import ResultsPage
from .theme import COLORS
from .widgets import label, muted, vspacer

PAGE_DASHBOARD = 0
PAGE_RESULTS = 1
PAGE_REPORT = 2


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} — offline secret scanner")
        self.setMinimumSize(1080, 700)
        self.resize(1240, 820)
        self._result: ScanResult | None = None

        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_sidebar())
        self._stack = QStackedWidget()
        root.addWidget(self._stack, stretch=1)

        self._dashboard = DashboardPage()
        self._results = ResultsPage()
        self._report = ReportPage()

        self._stack.addWidget(self._dashboard)
        self._stack.addWidget(self._results)
        self._stack.addWidget(self._report)

        # Wiring
        self._dashboard.scan_completed.connect(self._on_scan_completed)
        self._dashboard.show_results.connect(lambda: self._go(PAGE_RESULTS))
        self._dashboard.open_report.connect(lambda r: self._go(PAGE_REPORT))
        self._results.open_report.connect(lambda r: self._go(PAGE_REPORT))

    # ------------------------------------------------------------------ UI
    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setFixedWidth(236)
        sidebar.setStyleSheet(
            f"QFrame {{ background: {COLORS['bg']}; border: none; "
            f"border-right: 1px solid {COLORS['card_border']}; }}"
        )
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 24, 0, 16)
        layout.setSpacing(6)

        # Brand
        brand = QHBoxLayout()
        brand.setContentsMargins(18, 0, 18, 0)
        brand.setSpacing(10)

        mark = QLabel("S")
        mark.setFixedSize(34, 34)
        mark.setAlignment(Qt.AlignCenter)
        mark.setStyleSheet(
            f"QLabel {{ background: {COLORS['accent']}; color: {COLORS['accent_text']}; "
            f"border-radius: 8px; font-size: 17px; font-weight: 800; }}"
        )
        brand.addWidget(mark)

        brand_text = QVBoxLayout()
        brand_text.setSpacing(0)
        name = label(APP_NAME)
        name.setStyleSheet("font-size: 15px; font-weight: 800;")
        name.setWordWrap(False)
        name.setTextInteractionFlags(Qt.NoTextInteraction)
        brand_text.addWidget(name)
        tagline = muted("Offline secret scanner")
        tagline.setWordWrap(False)
        tagline.setTextInteractionFlags(Qt.NoTextInteraction)
        brand_text.addWidget(tagline)
        brand.addLayout(brand_text, stretch=1)
        layout.addLayout(brand)

        layout.addSpacing(26)

        # Nav buttons
        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)
        self._nav_rows: dict[int, QPushButton] = {}
        for index, title_ in [
            (PAGE_DASHBOARD, "Dashboard"),
            (PAGE_RESULTS, "Results"),
            (PAGE_REPORT, "Report"),
        ]:
            btn = QPushButton(title_)
            btn.setProperty("role", "nav")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            self._nav_group.addButton(btn, index)
            self._nav_rows[index] = btn
            layout.addWidget(btn)

        self._nav_group.idClicked.connect(self._go)

        layout.addWidget(vspacer())

        version = muted(f"v{__version__}")
        version.setAlignment(Qt.AlignCenter)
        version.setWordWrap(False)
        version.setTextInteractionFlags(Qt.NoTextInteraction)
        layout.addWidget(version)

        return sidebar

    # ------------------------------------------------------------- behavior
    def _go(self, page: int) -> None:
        if page in self._nav_rows:
            self._nav_rows[page].setChecked(True)
        self._stack.setCurrentIndex(page)

    def _on_scan_completed(self, result: ScanResult) -> None:
        self._result = result
        self._results.set_result(result)
        self._report.set_result(result)

    # For other modules / testing
    def dashboard(self) -> DashboardPage:
        return self._dashboard

    def results(self) -> ResultsPage:
        return self._results

    def report(self) -> ReportPage:
        return self._report