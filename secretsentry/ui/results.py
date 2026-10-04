"""Results: findings table, filters, search, and the redacted detail panel."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ..models import Finding, ScanResult
from .findings_model import COLUMNS, FindingFilterProxy, FindingsModel
from .theme import COLORS
from .widgets import (
    card,
    divider,
    label,
    muted,
    section,
    subtitle,
    title,
    vbox,
    vspacer,
)


class DetailsPanel(QWidget):
    """Right-hand panel showing a single redacted finding."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumWidth(360)
        self._build_ui()
        self.clear()

    def _build_ui(self) -> None:
        layout = vbox(self, margins=0, spacing=0)
        layout.setContentsMargins(18, 10, 18, 18)

        self._empty = QWidget()
        empty_layout = QVBoxLayout(self._empty)
        empty_layout.addStretch(1)
        empty_title = muted("Select a finding")
        empty_title.setAlignment(Qt.AlignCenter)
        empty_layout.addWidget(empty_title)
        empty_hint = muted("Details will appear here.")
        empty_hint.setAlignment(Qt.AlignCenter)
        empty_layout.addWidget(empty_hint)
        empty_layout.addStretch(1)
        layout.addWidget(self._empty)

        self._body = QWidget()
        body = QVBoxLayout(self._body)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(12)

        # Header row: badges
        badges = QHBoxLayout()
        self._sev_badge = QLabel("INFO")
        self._conf_badge = QLabel("LOW")
        self._occurrences_badge = QLabel("×1")
        for lbl in (self._sev_badge, self._conf_badge, self._occurrences_badge):
            lbl.setAlignment(Qt.AlignCenter)
            badges.addWidget(lbl)
        badges.addStretch(1)
        body.addLayout(badges)

        body.addWidget(section("Detection type"))
        self._type = label(object_name="pageSubtitle")
        self._type.setStyleSheet("font-size: 15px; font-weight: 600; color: #1C1917;")
        body.addWidget(self._type)
        self._category = muted("")
        body.addWidget(self._category)

        body.addWidget(divider())

        body.addWidget(section("Location"))
        self._file = label(object_name="codeText")
        self._file.setStyleSheet(
            f"background: transparent; color: #1C1917; font-family: 'Consolas', monospace; "
            f"font-size: 12px; padding: 0px; border: none;"
        )
        self._file.setObjectName("")
        body.addWidget(self._file)
        self._line = muted("")
        body.addWidget(self._line)

        body.addWidget(divider())

        body.addWidget(section("Redacted value"))
        code = QFrame()
        code.setObjectName("codeBox")
        code_layout = QHBoxLayout(code)
        code_layout.setContentsMargins(0, 0, 0, 0)
        self._value = label(object_name="codeAccent")
        code_layout.addWidget(self._value)
        body.addWidget(code)

        copy_btn = QPushButton("Copy redacted value")
        copy_btn.setProperty("role", "ghost")
        copy_btn.clicked.connect(self._copy_redacted)
        body.addWidget(copy_btn)

        body.addWidget(divider())

        body.addWidget(section("Line preview"))
        preview = QFrame()
        preview.setObjectName("codeBox")
        preview_layout = QHBoxLayout(preview)
        preview_layout.setContentsMargins(0, 0, 0, 0)
        self._context = label(object_name="codeText")
        preview_layout.addWidget(self._context)
        body.addWidget(preview)

        body.addWidget(divider())

        meta = QHBoxLayout()
        meta.addWidget(muted("Entropy"))
        self._entropy = muted("—")
        meta.addStretch(1)
        meta.addWidget(self._entropy)
        body.addLayout(meta)

        conf = QHBoxLayout()
        conf.addWidget(muted("Description"))
        self._description = muted("")
        conf.addStretch(1)
        body.addLayout(conf)

        body.addWidget(vspacer())
        layout.addWidget(self._body)

    # -- selection ------------------------------------------------------------
    def set_finding(self, finding: Finding) -> None:
        self._empty.setVisible(False)
        self._body.setVisible(True)

        sev_style = {
            "background": self._level_soft(finding.severity.value),
            "color": COLORS[{"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}[finding.severity.value]],
        }
        conf_color = COLORS["text_secondary"]
        self._style_badge(self._sev_badge, finding.severity.label.upper(), sev_style["color"], sev_style["background"])
        self._style_badge(self._conf_badge, finding.confidence.label.upper(), conf_color, COLORS["bg_soft"])
        self._style_badge(self._occurrences_badge, f"×{finding.occurrences}", COLORS["text_secondary"], COLORS["bg_soft"])

        self._type.setText(finding.pattern_name)
        self._category.setText(f"{finding.category} · {finding.pattern_id}")
        self._file.setText(finding.relative_path)
        self._line.setText(f"Line {finding.line_number}")
        self._value.setText(finding.redacted)
        self._context.setText(finding.context_redacted or "—")
        self._entropy.setText(
            f"{finding.entropy:.2f} bits/char" if finding.entropy is not None else "—"
        )
        self._description.setText(finding.description or "—")
        self._current = finding

    @staticmethod
    def _level_soft(severity: str) -> str:
        return {
            "critical": COLORS["critical_soft"],
            "high": COLORS["high_soft"],
            "medium": COLORS["medium_soft"],
            "low": COLORS["low_soft"],
            "info": COLORS["info_soft"],
        }[severity]

    @staticmethod
    def _style_badge(lbl: QLabel, text: str, color: str, soft: str) -> None:
        lbl.setText(text)
        lbl.setStyleSheet(
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

    def clear(self) -> None:
        self._empty.setVisible(True)
        self._body.setVisible(False)
        self._current = None

    def _copy_redacted(self) -> None:
        if self._current is not None:
            QGuiApplication.clipboard().setText(self._current.redacted)


class ResultsPage(QWidget):
    open_report = Signal(object)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._result: ScanResult | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = vbox(self, margins=28, spacing=14)

        # Header
        header = QHBoxLayout()
        header_col = QVBoxLayout()
        header_col.setSpacing(2)
        header_col.addWidget(title("Scan results"))
        self._context_label = subtitle("Run a scan to populate results.")
        header_col.addWidget(self._context_label)
        header.addLayout(header_col, stretch=1)

        self._export_btn = QPushButton("Open report")
        self._export_btn.setProperty("role", "ghost")
        self._export_btn.setEnabled(False)
        self._export_btn.clicked.connect(self._open_report)
        header.addWidget(self._export_btn)
        layout.addLayout(header)

        # Findings card
        results_card = card()
        results_card.layout().setContentsMargins(0, 0, 0, 0)
        results_card.layout().setSpacing(0)

        filter_bar = QHBoxLayout()
        filter_bar.setContentsMargins(16, 14, 16, 12)
        filter_bar.setSpacing(10)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Search file, type, or value…")
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._apply_filters)
        filter_bar.addWidget(self._search, stretch=1)

        self._sev_filter = QComboBox()
        self._sev_filter.addItem("All severities", None)
        for sev, name in [("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low"), ("info", "Info")]:
            self._sev_filter.addItem(name, sev)
        self._sev_filter.setFixedWidth(150)
        self._sev_filter.currentIndexChanged.connect(self._apply_filters)
        filter_bar.addWidget(self._sev_filter)

        self._conf_filter = QComboBox()
        self._conf_filter.addItem("All confidence", None)
        self._conf_filter.addItem("High", "high")
        self._conf_filter.addItem("Medium", "medium")
        self._conf_filter.addItem("Low", "low")
        self._conf_filter.setFixedWidth(150)
        self._conf_filter.currentIndexChanged.connect(self._apply_filters)
        filter_bar.addWidget(self._conf_filter)

        self._count_label = muted("")
        filter_bar.addWidget(self._count_label)
        results_card.layout().addLayout(filter_bar)

        # Splitter: table left, details right
        splitter = QSplitter()
        splitter.setContentsMargins(0, 0, 0, 0)

        table_container = QWidget()
        table_layout = QVBoxLayout(table_container)
        table_layout.setContentsMargins(16, 0, 0, 16)
        table_layout.setSpacing(0)

        self._table = QTableView()
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(True)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setShowGrid(False)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(False)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        table_layout.addWidget(self._table)
        splitter.addWidget(table_container)

        details = card()  # card styles the side panel frame
        details.layout().setContentsMargins(0, 0, 0, 0)
        details_layout = QVBoxLayout(details)
        details_layout.setContentsMargins(0, 0, 0, 0)
        self._details = DetailsPanel()
        details_layout.addWidget(self._details)
        splitter.addWidget(details)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([760, 400])
        results_card.layout().addWidget(splitter, stretch=1)

        layout.addWidget(results_card, stretch=1)

        self._selection_connected = False

    # ---- data ----------------------------------------------------------------
    def set_result(self, result: ScanResult) -> None:
        self._result = result
        model = FindingsModel(result.findings, self)
        proxy = FindingFilterProxy(self)
        proxy.setSourceModel(model)

        self._table.setModel(proxy)
        if not self._selection_connected:
            selection_model = self._table.selectionModel()
            if selection_model is not None:
                selection_model.selectionChanged.connect(self._on_selection)
                self._selection_connected = True
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(COLUMNS.index(("value", "Redacted value")) + 1, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(COLUMNS.index(("file", "File")) + 1, QHeaderView.Stretch)
        for col_idx, (key, _) in enumerate(COLUMNS):
            if key == "severity":
                self._table.setColumnWidth(col_idx, 96)
            elif key == "confidence":
                self._table.setColumnWidth(col_idx, 96)
            elif key == "line":
                self._table.setColumnWidth(col_idx, 56)
            elif key == "type":
                self._table.setColumnWidth(col_idx, 190)
            elif key == "entropy":
                self._table.setColumnWidth(col_idx, 84)

        self._table.sortByColumn(0, Qt.AscendingOrder)
        self._table.selectRow(0)

        self._context_label.setText(
            f"{len(result.findings)} findings · {result.source_type} · {result.source}"
        )
        self._export_btn.setEnabled(True)
        self._apply_filters()

    def reset(self) -> None:
        self._result = None
        self._export_btn.setEnabled(False)
        self._context_label.setText("Run a scan to populate results.")
        self._details.clear()

    # ---- filters ------------------------------------------------------------
    def _apply_filters(self) -> None:
        proxy = self._table.model()
        if isinstance(proxy, FindingFilterProxy):
            proxy.set_search(self._search.text())
            proxy.set_severity(self._sev_filter.currentData())
            proxy.set_confidence(self._conf_filter.currentData())
            self._count_label.setText(f"{proxy.rowCount()} showing")

    def _on_selection(self, selected, _deselected) -> None:
        indexes = selected.indexes()
        if not indexes:
            self._details.clear()
            return
        proxy = self._table.model()
        if not isinstance(proxy, FindingFilterProxy):
            return
        source_index = proxy.mapToSource(indexes[0])
        model = proxy.sourceModel()
        if isinstance(model, FindingsModel) and source_index.isValid():
            self._details.set_finding(model.finding_at(source_index.row()))

    def _open_report(self) -> None:
        if self._result is not None:
            self.open_report.emit(self._result)