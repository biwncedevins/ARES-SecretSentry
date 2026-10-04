"""Data models shared across the scanner engine and the UI."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def label(self) -> str:
        return self.value.capitalize()

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.index(self)


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def label(self) -> str:
        return self.value.capitalize()

    @property
    def rank(self) -> int:
        return CONFIDENCE_ORDER.index(self)


SEVERITY_ORDER: list[Severity] = [s for s in Severity]
CONFIDENCE_ORDER: list[Confidence] = [c for c in Confidence]


@dataclass(frozen=True)
class RawMatch:
    """A raw hit produced by a detector against a single line of text."""

    value: str
    start: int
    end: int
    detector: "Detector"

    @property
    def weight(self) -> int:
        return self.detector.weight


@dataclass(frozen=True)
class Finding:
    """A deduplicated, ready-to-display finding. Never contains an unwrapped secret."""

    file_path: str               # absolute path on disk (or original zip path source)
    relative_path: str           # path relative to the scan root, POSIX style
    line_number: int
    pattern_id: str
    pattern_name: str
    category: str
    severity: Severity
    confidence: Confidence
    redacted: str
    entropy: Optional[float]
    context_redacted: str = ""
    occurrences: int = 1
    description: str = ""
    # Transient only: used for dedupe in memory. Never serialized to reports/logs.
    raw_value: str = field(default="", repr=False)

    @property
    def signature(self) -> str:
        digest = hashlib.sha1()
        digest.update(self.pattern_id.encode("utf-8", "replace"))
        digest.update(b"::")
        digest.update(self.raw_value.encode("utf-8", "replace"))
        return digest.hexdigest()

    def to_dict(self) -> dict:
        return {
            "file": self.relative_path,
            "line": self.line_number,
            "pattern_id": self.pattern_id,
            "pattern_name": self.pattern_name,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "redacted": self.redacted,
            "entropy": None if self.entropy is None else round(self.entropy, 3),
            "occurrences": self.occurrences,
        }


@dataclass
class ScanStats:
    files_scanned: int = 0
    files_skipped_ignored: int = 0
    files_skipped_binary: int = 0
    files_skipped_large: int = 0
    files_skipped_other: int = 0
    bytes_read: int = 0
    findings_total: int = 0
    unique_secrets: int = 0

    @property
    def files_skipped(self) -> int:
        return (
            self.files_skipped_ignored
            + self.files_skipped_binary
            + self.files_skipped_large
            + self.files_skipped_other
        )

    def to_dict(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "files_skipped_ignored": self.files_skipped_ignored,
            "files_skipped_binary": self.files_skipped_binary,
            "files_skipped_large": self.files_skipped_large,
            "bytes_read": self.bytes_read,
            "findings_total": self.findings_total,
            "unique_secrets": self.unique_secrets,
        }


@dataclass
class ScanResult:
    source: str                 # path the user selected
    source_type: str            # folder | zip | git
    scan_root: str              # resolved directory that was walked
    started_at: str             # ISO timestamp
    duration_ms: int
    findings: list[Finding]
    stats: ScanStats
    notes: list[str] = field(default_factory=list)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for s in SEVERITY_ORDER:
            counts[s.value] = 0
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def confidence_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for c in CONFIDENCE_ORDER:
            counts[c.value] = 0
        for f in self.findings:
            counts[f.confidence.value] += 1
        return counts

    def summary_dict(self) -> dict:
        return {
            "source": self.source,
            "source_type": self.source_type,
            "scan_root": self.scan_root,
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
            "stats": self.stats.to_dict(),
            "summary": {
                "total": len(self.findings),
                "by_severity": self.severity_counts,
                "by_confidence": self.confidence_counts,
            },
            "notes": self.notes,
        }