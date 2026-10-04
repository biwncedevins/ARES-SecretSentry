"""Table model and filter proxy for the findings list."""

from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor

from ..models import Finding
from .theme import COLORS, severity_color

COLUMNS = [
    ("severity", "Severity"),
    ("confidence", "Confidence"),
    ("file", "File"),
    ("line", "Line"),
    ("type", "Type"),
    ("value", "Redacted value"),
    ("entropy", "Entropy"),
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


class FindingsModel(QAbstractTableModel):
    def __init__(self, findings: list[Finding], parent=None) -> None:
        super().__init__(parent)
        self._findings = findings

    @property
    def findings(self) -> list[Finding]:
        return self._findings

    # -- Qt API ---------------------------------------------------------------
    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._findings)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return COLUMNS[section][1]
        return None

    def data(self, index, role=Qt.DisplayRole):  # noqa: N802
        if not index.isValid():
            return None
        finding = self._findings[index.row()]
        col = COLUMNS[index.column()][0]

        if role == Qt.DisplayRole:
            if col == "severity":
                return finding.severity.label
            if col == "confidence":
                return finding.confidence.label
            if col == "file":
                return finding.relative_path
            if col == "line":
                return str(finding.line_number)
            if col == "type":
                return finding.pattern_name
            if col == "value":
                return finding.redacted
            if col == "entropy":
                return f"{finding.entropy:.2f}" if finding.entropy is not None else "—"
            return None

        if role == Qt.ForegroundRole:
            if col == "severity":
                return QColor(severity_color(finding.severity.value))
            if col == "confidence":
                return QColor(COLORS["text_secondary"])
            return QColor(COLORS["text"])

        if role == Qt.UserRole:  # numeric sort keys
            if col == "severity":
                return SEVERITY_ORDER.get(finding.severity.value, 99)
            if col == "confidence":
                return CONFIDENCE_ORDER.get(finding.confidence.value, 99)
            if col == "line":
                return finding.line_number
            if col == "entropy":
                return finding.entropy or -1.0
            return self.data(index, Qt.DisplayRole)

        if role == Qt.ToolTipRole:
            if col == "value":
                return finding.redacted
            if col == "file":
                return finding.relative_path
            return None

        return None

    def finding_at(self, row: int) -> Finding:
        return self._findings[row]


class FindingFilterProxy(QSortFilterProxyModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._search = ""
        self._severity = None      # None = all
        self._confidence = None    # None = all
        self.setDynamicSortFilter(True)

    # -- filters ---------------------------------------------------------------
    def set_search(self, text: str) -> None:
        self._search = text.strip().lower()
        self.invalidateFilter()

    def set_severity(self, value: str | None) -> None:
        self._severity = value
        self.invalidateFilter()

    def set_confidence(self, value: str | None) -> None:
        self._confidence = value
        self.invalidateFilter()

    def filterAcceptsRow(self, row, parent):  # noqa: N802
        model = self.sourceModel()
        if model is None or parent.isValid():
            return False
        if row >= model.rowCount():
            return False
        finding = model.findings[row]

        if self._severity and finding.severity.value != self._severity:
            return False
        if self._confidence and finding.confidence.value != self._confidence:
            return False
        if self._search:
            haystack = " ".join([
                finding.relative_path,
                finding.pattern_name,
                finding.pattern_id,
                finding.category,
                finding.redacted,
                finding.severity.value,
                finding.confidence.value,
            ]).lower()
            if self._search not in haystack:
                return False
        return True

    def lessThan(self, left, right):  # noqa: N802
        left_val = left.data(Qt.UserRole)
        right_val = right.data(Qt.UserRole)
        left_display = left.data(Qt.DisplayRole)
        right_display = right.data(Qt.DisplayRole)

        if isinstance(left_val, (int, float)) and isinstance(right_val, (int, float)):
            return left_val < right_val
        return str(left_display).lower() < str(right_display).lower()