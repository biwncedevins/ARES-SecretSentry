"""Dashboard: choose a source, run a scan, show progress and mini-stats."""

from __future__ import annotations

import zipfile
from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QWidget,
)

from ..models import ScanResult
from ..scanner import detect_source_type
from .theme import COLORS
from .widgets import (
    card,
    hint,
    muted,
    section,
    stat_label,
    stat_value,
    subtitle,
    title,
    vbox,
    vspacer,
)
from .worker import ScanWorker


class DashboardPage(QWidget):
    scan_completed = Signal(object)   # ScanResult
    show_results = Signal()
    open_report = Signal(object)      # ScanResult

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._result: ScanResult | None = None
        self._worker: ScanWorker | None = None
        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = vbox(self, margins=28, spacing=18)

        # Header
        layout.addWidget(title("Scan your code for leaked secrets"))
        layout.addWidget(subtitle(
            "Choose a folder, ZIP archive, or Git working tree. SecretSentry scans it "
            "fully offline and never sends anything anywhere."
        ))

        # Source selection card
        source_card = card()
        source_card.layout().addWidget(section("1 · What would you like to scan?"))
        row = QHBoxLayout()
        row.setSpacing(10)

        self._type_box = QComboBox()
        self._type_box.addItem("📁  Folder", "folder")
        self._type_box.addItem("🗜️  ZIP archive", "zip")
        self._type_box.addItem("🌿  Git working tree", "git")
        self._type_box.setFixedWidth(220)
        self._type_box.currentIndexChanged.connect(self._on_type_changed)
        row.addWidget(self._type_box)

        self._path_edit = QLineEdit()
        self._path_edit.setPlaceholderText("Pick a folder or .zip file…")
        self._path_edit.setReadOnly(True)
        self._path_edit.textChanged.connect(self._on_path_changed)
        row.addWidget(self._path_edit, stretch=1)

        browse_btn = QPushButton("Browse…")
        browse_btn.setProperty("role", "ghost")
        browse_btn.clicked.connect(self._browse)
        row.addWidget(browse_btn)

        self._start_btn = QPushButton("Start scan")
        self._start_btn.setProperty("role", "primary")
        self._start_btn.setEnabled(False)
        self._start_btn.clicked.connect(self._start_scan)
        row.addWidget(self._start_btn)

        source_card.layout().addLayout(row)
        self._source_note = muted("")
        source_card.layout().addWidget(self._source_note)
        layout.addWidget(source_card)

        # Ignore rules explainer
        hint_card = card("soft")
        hint_card.layout().addWidget(section("Automatic exclusions"))
        hint_card.layout().addWidget(hint(
            "Skipped by default: .git, node_modules, vendor, __pycache__, dist, build, "
            "*.min.js, binary files and files over 5 MB.\n\n"
            "Add a .cyberignore file in the scan root for your own rules "
            "(gitignore syntax: # comment, ! re-include, ** glob). Git working trees "
            "also respect the repository's .gitignore."
        ))
        layout.addWidget(hint_card)

        # Progress card
        self._progress_card = card()
        self._progress_card.setVisible(False)
        self._progress_card.layout().addWidget(section("Scanning…"))
        self._progress_bar = QProgressBar()
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setRange(0, 100)
        self._progress_card.layout().addWidget(self._progress_bar)
        self._status_label = muted("")
        self._progress_card.layout().addWidget(self._status_label)

        progress_row = QHBoxLayout()
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setProperty("role", "ghost")
        self._cancel_btn.clicked.connect(self._cancel_scan)
        progress_row.addWidget(self._cancel_btn)
        progress_row.addStretch(1)
        self._elapsed_label = muted("")
        progress_row.addWidget(self._elapsed_label)
        progress_row.addStretch(1)
        self._progress_card.layout().addLayout(progress_row)

        layout.addWidget(self._progress_card)

        # Results summary card (shown after a scan)
        self._summary_card = card()
        self._summary_card.setVisible(False)
        layout.addWidget(self._summary_card)

        self._summary_card.layout().addWidget(section("Scan complete"))

        grid = QGridLayout()
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(10)
        self._stat_files = stat_value("0")
        self._stat_elapsed = stat_value("0 s")
        self._stat_findings = stat_value("0")
        self._stat_critical = stat_value("0", color=COLORS["critical"])
        self._stat_high = stat_value("0", color=COLORS["high"])

        grid.addWidget(stat_label("Files scanned"), 0, 0)
        grid.addWidget(self._stat_files, 1, 0)
        grid.addWidget(stat_label("Duration"), 0, 1)
        grid.addWidget(self._stat_elapsed, 1, 1)
        grid.addWidget(stat_label("Findings"), 0, 2)
        grid.addWidget(self._stat_findings, 1, 2)
        grid.addWidget(stat_label("Critical"), 0, 3)
        grid.addWidget(self._stat_critical, 1, 3)
        grid.addWidget(stat_label("High"), 0, 4)
        grid.addWidget(self._stat_high, 1, 4)
        self._summary_card.layout().addLayout(grid)

        summary_actions = QHBoxLayout()
        self._results_btn = QPushButton("Review findings")
        self._results_btn.setProperty("role", "primary")
        self._results_btn.setEnabled(False)
        self._results_btn.clicked.connect(self.show_results.emit)
        summary_actions.addWidget(self._results_btn)

        self._report_btn = QPushButton("Open report")
        self._report_btn.setProperty("role", "ghost")
        self._report_btn.setEnabled(False)
        self._report_btn.clicked.connect(self._open_report)
        summary_actions.addWidget(self._report_btn)
        summary_actions.addStretch(1)
        self._summary_card.layout().addLayout(summary_actions)

        layout.addWidget(vspacer())

    # ------------------------------------------------------------- behaviour
    def _on_type_changed(self) -> None:
        self._refresh_note()

    def _on_path_changed(self) -> None:
        self._refresh_note()

    def _refresh_note(self) -> None:
        path_text = self._path_edit.text()
        selected_type = self._type_box.currentData()
        note = ""

        if path_text:
            path = Path(path_text)
            if selected_type == "zip":
                note = "ZIP archive selected. Contents are extracted to a temporary folder for scanning."
            elif path.is_dir():
                has_git = (path / ".git").is_dir()
                is_git_type = selected_type == "git"
                if has_git and not is_git_type:
                    note = "This folder is a Git working tree — .gitignore will be respected."
                elif is_git_type and not has_git:
                    note = "No .git directory found here; scanning as a plain folder."
                elif is_git_type and has_git:
                    note = "Git working tree selected — .gitignore will be respected."
            elif path.is_file():
                note = "The selected path is a file."

        self._source_note.setText(note)

        valid = False
        if path_text and Path(path_text).exists():
            if selected_type == "zip" or selected_type == "git":
                valid = True
            elif Path(path_text).is_dir():
                valid = True
        self._start_btn.setEnabled(valid and self._worker is None)

    def _browse(self) -> None:
        selected = self._type_box.currentData()
        if selected == "zip":
            path, _ = QFileDialog.getOpenFileName(
                self, "Select a ZIP archive", "", "ZIP archives (*.zip);;All files (*)"
            )
        else:
            path = QFileDialog.getExistingDirectory(self, "Select a folder to scan")
        if path:
            self._path_edit.setText(path)
            if zipfile.is_zipfile(path):
                idx = self._type_box.findData("zip")
                self._type_box.setCurrentIndex(idx)

    def _start_scan(self) -> None:
        path = self._path_edit.text().strip()
        if not path:
            return
        kind = self._type_box.currentData()
        self._progress_card.setVisible(True)
        self._summary_card.setVisible(False)
        self._results_btn.setEnabled(False)
        self._report_btn.setEnabled(False)
        self._start_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)
        self._progress_bar.setValue(0)
        self._status_label.setText("Starting…")
        self._elapsed_label.setText("")

        if kind == "zip" and not zipfile.is_zipfile(path):
            kind = detect_source_type(path)

        self._worker = ScanWorker(path, kind, self)
        self._worker.progress.connect(self._on_progress)
        self._worker.scan_finished.connect(self._on_finished)
        self._worker.scan_failed.connect(self._on_failed)
        self._worker.scan_cancelled.connect(self._on_cancelled)
        self._worker.start()

    def _on_progress(self, done: int, total: int, message: str) -> None:
        if total:
            self._progress_bar.setValue(int(done * 100 / total))
        self._status_label.setText(message)

    def _on_finished(self, result: ScanResult) -> None:
        self._worker = None
        self._result = result
        self._progress_bar.setValue(100)
        self._status_label.setText("Scan complete")
        self._cancel_btn.setEnabled(False)

        self._progress_card.setVisible(False)
        self._summary_card.setVisible(True)

        severity = result.severity_counts
        self._stat_files.setText(str(result.stats.files_scanned))
        self._stat_elapsed.setText(f"{result.duration_ms / 1000:.1f} s")
        self._stat_findings.setText(str(len(result.findings)))
        self._stat_critical.setText(str(severity.get("critical", 0)))
        self._stat_high.setText(str(severity.get("high", 0)))

        has_findings = len(result.findings) > 0
        self._results_btn.setEnabled(True)
        self._report_btn.setEnabled(True)
        self._start_btn.setEnabled(True)
        self.scan_completed.emit(result)

    def _on_failed(self, message: str) -> None:
        self._worker = None
        self._cancel_btn.setEnabled(False)
        self._progress_card.setVisible(False)
        self._start_btn.setEnabled(True)
        self._status_label.setText(f"Scan failed: {message}")

    def _on_cancelled(self) -> None:
        self._worker = None
        self._cancel_btn.setEnabled(False)
        self._start_btn.setEnabled(True)
        self._progress_card.setVisible(False)
        self._progress_bar.setValue(0)

    def _cancel_scan(self) -> None:
        if self._worker is not None:
            self._status_label.setText("Cancelling…")
            self._cancel_btn.setEnabled(False)
            self._worker.cancel()

    def _open_report(self) -> None:
        if self._result is not None:
            self.open_report.emit(self._result)

    def current_result(self) -> ScanResult | None:
        return self._result

    def set_default_source(self, path: str) -> None:
        if path:
            self._path_edit.setText(path)
            self._refresh_note()