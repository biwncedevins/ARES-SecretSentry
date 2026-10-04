"""Report: scan summary, severity breakdown, and JSON/CSV export."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QGridLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..models import ScanResult
from ..reporting import save_report
from .theme import COLORS
from .widgets import (
    card,
    hbox,
    muted,
    section,
    stat_label,
    stat_value,
    subtitle,
    title,
    vbox,
)


class ReportPage(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._result: ScanResult | None = None
        self._export_path: Path | None = None
        self._build_ui()
        self.show_empty()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = vbox(self, margins=28, spacing=18)

        layout.addWidget(title("Report"))
        self._context_label = subtitle("Run a scan to generate a report.")
        layout.addWidget(self._context_label)

        # Top summary stats
        self._summary_card = card()
        grid = QGridLayout()
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(10)
        self._total_findings = stat_value("0")
        self._files_scanned = stat_value("0")
        self._files_skipped = stat_value("0")
        self._duration = stat_value("0 s")
        self._bytes = stat_value("0")

        grid.addWidget(stat_label("Findings"), 0, 0)
        grid.addWidget(self._total_findings, 1, 0)
        grid.addWidget(stat_label("Files scanned"), 0, 1)
        grid.addWidget(self._files_scanned, 1, 1)
        grid.addWidget(stat_label("Files skipped"), 0, 2)
        grid.addWidget(self._files_skipped, 1, 2)
        grid.addWidget(stat_label("Duration"), 0, 3)
        grid.addWidget(self._duration, 1, 3)
        grid.addWidget(stat_label("Bytes read"), 0, 4)
        grid.addWidget(self._bytes, 1, 4)
        self._summary_card.layout().addLayout(grid)
        layout.addWidget(self._summary_card)

        # Severity breakdown
        severity_card = card()
        severity_card.layout().addWidget(section("Findings by severity"))
        self._severity_box = QVBoxLayout()
        self._severity_box.setSpacing(10)
        self._severity_bars: dict[str, QProgressBar] = {}
        self._severity_counts: dict[str, QLabel] = {}
        order = ["critical", "high", "medium", "low", "info"]
        names = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
        for sev in order:
            row = hbox()
            name = QLabel(names[sev])
            name.setFixedWidth(90)
            name.setWordWrap(False)
            row.addWidget(name)
            bar = QProgressBar()
            bar.setTextVisible(False)
            bar.setRange(0, 100)
            bar.setFixedHeight(10)
            color = {
                "critical": COLORS["critical"],
                "high": COLORS["high"],
                "medium": COLORS["medium"],
                "low": COLORS["low"],
                "info": COLORS["info"],
            }[sev]
            bar.setStyleSheet(
                f"QProgressBar {{ background: #F5F5F4; border: none; border-radius: 5px; }}"
                f"QProgressBar::chunk {{ background: {color}; border-radius: 5px; }}"
            )
            row.addWidget(bar, stretch=1)
            count = QLabel("0")
            count.setFixedWidth(42)
            count.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            count.setWordWrap(False)
            row.addWidget(count)
            self._severity_box.addLayout(row)
            self._severity_bars[sev] = bar
            self._severity_counts[sev] = count
        severity_card.layout().addLayout(self._severity_box)
        layout.addWidget(severity_card)

        # Entry details
        detail_card = card()
        detail_card.layout().addWidget(section("Scan details"))
        detail_grid = QGridLayout()
        detail_grid.setHorizontalSpacing(24)
        detail_grid.setVerticalSpacing(8)
        detail_grid.addWidget(stat_label("Source type"), 0, 0)
        self._detail_type = muted("—")
        detail_grid.addWidget(self._detail_type, 1, 0)
        detail_grid.addWidget(stat_label("Target"), 0, 1)
        self._detail_source = muted("—")
        detail_grid.addWidget(self._detail_source, 1, 1, 1, 3)
        detail_grid.addWidget(stat_label("Started"), 0, 4)
        self._detail_started = muted("—")
        detail_grid.addWidget(self._detail_started, 1, 4)
        detail_grid.addWidget(stat_label("Skipped — ignored"), 0, 5)
        self._detail_ignored = muted("0")
        detail_grid.addWidget(self._detail_ignored, 1, 5)
        detail_grid.addWidget(stat_label("Skipped — binary"), 0, 6)
        self._detail_binary = muted("0")
        detail_grid.addWidget(self._detail_binary, 1, 6)
        detail_grid.addWidget(stat_label("Skipped — large"), 0, 7)
        self._detail_large = muted("0")
        detail_grid.addWidget(self._detail_large, 1, 7)
        detail_card.layout().addLayout(detail_grid)
        layout.addWidget(detail_card)

        # Export
        export_card = card()
        export_card.layout().addWidget(section("Export report"))
        export_card.layout().addWidget(muted(
            "Reports include scan metadata and findings with redacted values only. "
            "Raw secrets are never written to disk."
        ))
        export_row = hbox()
        self._json_btn = QPushButton("Export JSON")
        self._json_btn.setProperty("role", "primary")
        self._json_btn.setEnabled(False)
        self._json_btn.clicked.connect(lambda: self._export("json"))
        export_row.addWidget(self._json_btn)

        self._csv_btn = QPushButton("Export CSV")
        self._csv_btn.setProperty("role", "ghost")
        self._csv_btn.setEnabled(False)
        self._csv_btn.clicked.connect(lambda: self._export("csv"))
        export_row.addWidget(self._csv_btn)
        export_row.addStretch(1)
        self._last_export = muted("")
        export_row.addWidget(self._last_export)
        export_card.layout().addLayout(export_row)
        layout.addWidget(export_card)

        layout.addStretch(1)

    # -------------------------------------------------------------- data
    def set_result(self, result: ScanResult) -> None:
        self._result = result
        self._context_label.setText(
            f"Scan of {result.source_type} · {result.source}"
        )

        counts = result.severity_counts
        self._total_findings.setText(str(len(result.findings)))
        self._files_scanned.setText(str(result.stats.files_scanned))
        self._files_skipped.setText(str(result.stats.files_skipped))
        self._duration.setText(f"{result.duration_ms / 1000:.1f} s")
        self._bytes.setText(f"{result.stats.bytes_read / 1024:.1f} KB")

        total = max(1, len(result.findings) or 1)
        for sev in self._severity_bars:
            count = counts.get(sev, 0)
            self._severity_bars[sev].setValue(int(count * 100 / total))
            self._severity_counts[sev].setText(str(count))

        self._detail_type.setText(result.source_type)
        self._detail_source.setText(str(result.source))
        self._detail_started.setText(str(result.started_at))
        self._detail_ignored.setText(str(result.stats.files_skipped_ignored))
        self._detail_binary.setText(str(result.stats.files_skipped_binary))
        self._detail_large.setText(str(result.stats.files_skipped_large))

        self._json_btn.setEnabled(True)
        self._csv_btn.setEnabled(True)
        self._export_path = None
        self._last_export.setText("")

    def show_empty(self) -> None:
        self._result = None
        self._context_label.setText("Run a scan to generate a report.")
        self._json_btn.setEnabled(False)
        self._csv_btn.setEnabled(False)
        self._last_export.setText("")

    # ------------------------------------------------------------- export
    def _export(self, kind: str) -> None:
        if self._result is None:
            return
        default = f"secretsentry-report-{datetime.now():%Y%m%d-%H%M%S}.{kind}"
        target, _ = QFileDialog.getSaveFileName(
            self, f"Export {kind.upper()} report", str(Path.home() / default),
            f"{kind.upper()} files (*.{kind})",
        )
        if not target:
            return
        path = Path(target)
        if path.suffix.lower() != f".{kind}":
            path = path.with_suffix(f".{kind}")
        save_report(self._result, path, kind)
        self._export_path = path
        self._last_export.setText(f"Saved: {path.name}")