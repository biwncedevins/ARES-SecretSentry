"""JSON / CSV report generation.

Safety guarantee: findings are serialized through ``Finding.to_dict()`` which has
no access to ``raw_value``. Reports contain redacted previews only.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from . import __version__
from .models import ScanResult

CSV_COLUMNS = [
    "severity",
    "confidence",
    "file",
    "line",
    "pattern_id",
    "pattern_name",
    "category",
    "redacted",
    "entropy",
    "occurrences",
]


def _build_report_dict(result: ScanResult) -> dict[str, Any]:
    return {
        "tool": "SecretSentry",
        "version": __version__,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "scan": result.summary_dict(),
        "findings": [f.to_dict() for f in result.findings],
    }


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(_build_report_dict(result), indent=indent, ensure_ascii=False)


def to_csv(result: ScanResult) -> str:
    import io

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow([f"SecretSentry report v{__version__}"])
    writer.writerow(["generated_at", datetime.now().isoformat(timespec="seconds")])
    writer.writerow(["scan_source", result.source])
    writer.writerow(["scan_type", result.source_type])
    writer.writerow(["files_scanned", result.stats.files_scanned])
    writer.writerow(["findings_total", len(result.findings)])
    writer.writerow([])
    writer.writerow(CSV_COLUMNS)
    for finding in result.findings:
        writer.writerow([finding.to_dict().get(col, "") for col in CSV_COLUMNS])
    return buffer.getvalue()


def default_report_name(extension: str, when: datetime | None = None) -> str:
    when = when or datetime.now()
    stamp = when.strftime("%Y%m%d-%H%M%S")
    return f"secretsentry-report-{stamp}.{extension}"


def write_report(result: ScanResult, target_dir: str, kind: str) -> Path:
    """Write a JSON or CSV report into ``target_dir`` and return the file path."""
    directory = Path(target_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / default_report_name(kind)
    save_report(result, path, kind)
    return path


def save_report(result: ScanResult, path: Path, kind: str) -> Path:
    """Write a report to an explicit path (used by the UI's save dialog)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "json":
        path.write_text(to_json(result), encoding="utf-8")
    elif kind == "csv":
        path.write_text(to_csv(result), encoding="utf-8-sig", newline="")
    else:
        raise ValueError(f"Unsupported report kind: {kind}")
    return path