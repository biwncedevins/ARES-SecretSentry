"""Background scan worker. Keeps scanning off the UI thread."""

from __future__ import annotations

from PySide6.QtCore import QThread, Signal

from ..scanner import ScanCancelled, ScanEngine


class ScanWorker(QThread):
    progress = Signal(int, int, str)      # done, total, message
    scan_finished = Signal(object)        # ScanResult
    scan_failed = Signal(str)
    scan_cancelled = Signal()

    def __init__(
        self,
        source: str,
        source_type: str,
        parent=None,
        include_generic: bool = True,
        max_file_bytes: int = 5 * 1024 * 1024,
    ) -> None:
        super().__init__(parent)
        self._source = source
        self._source_type = source_type
        self._include_generic = include_generic
        self._max_file_bytes = max_file_bytes
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def run(self) -> None:
        engine = ScanEngine(
            max_file_bytes=self._max_file_bytes,
            include_generic=self._include_generic,
        )
        try:
            result = engine.scan(
                self._source,
                source_type=self._source_type,
                on_progress=lambda done, total, msg: self.progress.emit(done, total, msg),
                should_cancel=lambda: self._cancel,
            )
        except ScanCancelled:
            self.scan_cancelled.emit()
            return
        except Exception as exc:  # noqa: BLE001 - surfaced to UI
            self.scan_failed.emit(str(exc))
            return
        self.scan_finished.emit(result)