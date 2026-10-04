"""The SecretSentry scan engine.

Implements the pipeline:

    SELECT → IGNORE → DETECT → ENTROPY → DEDUPE → REDACT → REPORT

The engine is pure Python (no Qt) so it can be embedded, tested, or driven from
a CLI without pulling in UI dependencies.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .config import (
    BINARY_EXTENSIONS,
    DEFAULT_MAX_FILE_BYTES,
    ENCODING_FALLBACKS,
    MAX_GENERIC_FINDINGS,
    SOURCE_FOLDER,
    SOURCE_GIT,
    SOURCE_ZIP,
)
from .detectors import DETECTOR_REGISTRY
from .entropy import shannon_entropy
from .ignore import load_ignore_rules
from .models import Confidence, Finding, RawMatch, ScanResult, ScanStats
from .redact import redact_block, redact_secret, slice_around

ProgressCallback = Callable[[int, int, str], None]
CancelCheck = Callable[[], bool]


class ScanCancelled(Exception):
    """Raised internally when the user cancels a scan."""


# Generic / entropy-driven detectors that would only re-flag the base64 body of a
# PEM-encoded block (private keys, public keys, certificates). Skipped inside blocks.
_PEM_BLOCK_NOISE_DETECTORS = frozenset({
    "high_entropy_string",
    "aws_secret_access_key",
    "bearer_token",
    "twilio_auth_token",
})


class ScanEngine:
    def __init__(
        self,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        include_generic: bool = True,
    ) -> None:
        self.max_file_bytes = max_file_bytes
        self.include_generic = include_generic
        if include_generic:
            self._disabled_ids: frozenset[str] = frozenset()
        else:
            self._disabled_ids = frozenset({"high_entropy_string", "twilio_auth_token"})

    # ------------------------------------------------------------------ API
    def scan(
        self,
        source: str,
        *,
        source_type: Optional[str] = None,
        on_progress: Optional[ProgressCallback] = None,
        should_cancel: Optional[CancelCheck] = None,
    ) -> ScanResult:
        started = datetime.now(timezone.utc)
        start_ms = time.monotonic()

        source_type = source_type or self._detect_source_type(source)
        if source_type == SOURCE_ZIP:
            with _ZipWorkspace(source) as workspace:
                scan_root = workspace.path
                results = self._scan_directory(
                    scan_root, relative_base=workspace.path,
                    on_progress=on_progress, should_cancel=should_cancel,
                )
        else:
            scan_path = Path(source)
            if not scan_path.is_dir():
                raise ValueError(f"Not a directory: {source}")
            results = self._scan_directory(
                scan_path, relative_base=scan_path,
                on_progress=on_progress, should_cancel=should_cancel,
            )

        duration_ms = int((time.monotonic() - start_ms) * 1000)
        findings = results[0]
        stats = results[1]

        result = ScanResult(
            source=source,
            source_type=source_type,
            scan_root=str(scan_path if source_type != SOURCE_ZIP else source),
            started_at=started.isoformat(timespec="seconds"),
            duration_ms=duration_ms,
            findings=findings,
            stats=stats,
        )
        result.notes = [
            "Exported reports never contain raw secret values; all values are redacted.",
            f"Detectors loaded: {len(DETECTOR_REGISTRY)}.",
        ]
        return result

    # ------------------------------------------------------------- selection
    @staticmethod
    def _detect_source_type(source: str) -> str:
        path = Path(source)
        if path.is_file() and zipfile.is_zipfile(path):
            return SOURCE_ZIP
        if path.is_dir():
            if (path / ".git").is_dir():
                return SOURCE_GIT
            return SOURCE_FOLDER
        raise ValueError(f"Path does not exist: {source}")

    # -------------------------------------------------------------- scanning
    def _scan_directory(
        self,
        scan_root: Path,
        relative_base: Path,
        on_progress: Optional[ProgressCallback],
        should_cancel: Optional[CancelCheck],
    ) -> tuple[list[Finding], ScanStats]:
        stats = ScanStats()
        findings: list[Finding] = []
        generic_count = 0

        matcher = load_ignore_rules(scan_root)
        prune_ignored = not matcher.has_negation

        if should_cancel and should_cancel():
            raise ScanCancelled()

        files, _ = self._enumerate_files(
            scan_root, relative_base, matcher, prune_ignored, stats
        )
        total = len(files)
        if on_progress:
            on_progress(0, total, "Preparing scan…")

        done = 0
        seen_signatures: dict[str, Finding] = {}

        for abs_path, rel_posix in files:
            if should_cancel and should_cancel():
                raise ScanCancelled()

            try:
                size = abs_path.stat().st_size
            except OSError:
                stats.files_skipped_other += 1
                done += 1
                continue

            if size > self.max_file_bytes:
                stats.files_skipped_large += 1
                done += 1
                if on_progress and (done % 20 == 0 or done == total):
                    on_progress(done, total, f"Skipped large file: {rel_posix}")
                continue

            if abs_path.suffix.lower() in BINARY_EXTENSIONS:
                stats.files_skipped_binary += 1
                done += 1
                if on_progress and (done % 20 == 0 or done == total):
                    on_progress(done, total, f"Skipped binary file: {rel_posix}")
                continue

            try:
                data = abs_path.read_bytes()
            except OSError:
                stats.files_skipped_other += 1
                done += 1
                continue

            if b"\x00" in data[:8192]:
                stats.files_skipped_binary += 1
                done += 1
                if on_progress and (done % 20 == 0 or done == total):
                    on_progress(done, total, f"Skipped binary file: {rel_posix}")
                continue

            text = _decode(data)
            stats.bytes_read += len(data)
            stats.files_scanned += 1

            file_found, generic_added = self._scan_text(
                abs_path, rel_posix, text, stats
            )
            generic_count += generic_added
            for finding in file_found:
                # Enforce a ceiling on generic (low-severity) hints so huge
                # generated trees do not drown real results.
                if finding.pattern_id == "high_entropy_string" and generic_count > MAX_GENERIC_FINDINGS:
                    continue
                key = finding.signature
                existing = seen_signatures.get(key)
                if existing is None:
                    seen_signatures[key] = finding
                    findings.append(finding)
                else:
                    object.__setattr__(existing, "occurrences", existing.occurrences + 1)

            done += 1
            if on_progress and (done % 20 == 0 or done == total):
                pct = int(done * 100 / total) if total else 100
                on_progress(done, total, f"Scanned {done}/{total} files")

        findings = self._sort_findings(findings)
        stats.findings_total = len(findings)
        stats.unique_secrets = len(findings)
        return findings, stats

    def _enumerate_files(
        self,
        scan_root: Path,
        relative_base: Path,
        matcher,
        prune_ignored: bool,
        stats: ScanStats,
    ) -> tuple[list[tuple[Path, str]], int]:
        files: list[tuple[Path, str]] = []
        ignored_dirs = 0

        for dirpath, dirnames, filenames in os.walk(scan_root, topdown=True):
            dir_abs = Path(dirpath)
            rel_dir = _relative_posix(dir_abs, relative_base)

            if prune_ignored:
                kept_dirs: list[str] = []
                for name in dirnames:
                    rel = f"{rel_dir}/{name}" if rel_dir else name
                    if matcher.ignored(rel, is_dir=True):
                        ignored_dirs += 1
                        continue
                    kept_dirs.append(name)
                dirnames[:] = kept_dirs

            for name in sorted(filenames):
                rel = f"{rel_dir}/{name}" if rel_dir else name
                if matcher.ignored(rel, is_dir=False):
                    stats.files_skipped_ignored += 1
                    continue
                files.append((dir_abs / name, rel))

        files.sort(key=lambda t: t[1])
        return files, ignored_dirs

    # --------------------------------------------------------------- detect
    def _scan_text(
        self,
        abs_path: Path,
        rel_posix: str,
        text: str,
        stats: ScanStats,
    ) -> tuple[list[Finding], int]:
        findings: list[Finding] = []
        generic_added = 0

        in_pem_block = False

        for line_no, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()

            if stripped.startswith("-----BEGIN"):
                in_pem_block = True

            matches: list[RawMatch] = []
            for det in DETECTOR_REGISTRY:
                if det.id in self._disabled_ids:
                    continue
                # Inside any PEM block, entropy-based generic detectors would only
                # re-flag the base64 body. The block header itself is already a
                # finding, so these would be pure noise.
                if in_pem_block and det.id in _PEM_BLOCK_NOISE_DETECTORS:
                    continue
                for m in det.find(stripped):
                    matches.append(m)

            if matches:
                kept = _dedupe_matches(matches)
                for rm in kept:
                    if rm.detector.id == "high_entropy_string":
                        generic_added += 1

                    entropy = shannon_entropy(rm.value)
                    if rm.detector.id == "private_key":
                        redacted = redact_block(rm.value)
                    else:
                        redacted = redact_secret(rm.value)

                    # Sanity: if a "credential" has nearly no entropy and is not a
                    # known-format key, it is probably a placeholder word.
                    conf = rm.detector.confidence
                    if (
                        conf is Confidence.HIGH
                        and entropy < 2.5
                        and rm.detector.min_entropy is None
                        and len(rm.value) < 40
                    ):
                        conf = Confidence.MEDIUM

                    span_line = stripped
                    context = slice_around(span_line, [(rm.start, rm.end)])

                    finding = Finding(
                        file_path=str(abs_path),
                        relative_path=rel_posix,
                        line_number=line_no,
                        pattern_id=rm.detector.id,
                        pattern_name=rm.detector.name,
                        category=rm.detector.category,
                        severity=rm.detector.severity,
                        confidence=conf,
                        redacted=redacted,
                        entropy=round(entropy, 3),
context_redacted=context,
                    raw_value=rm.value,
                    description=rm.detector.description,
                )
                    findings.append(finding)

            if stripped.startswith("-----END"):
                in_pem_block = False

        return findings, generic_added

    # --------------------------------------------------------------- sort
    @staticmethod
    def _sort_findings(findings: list[Finding]) -> list[Finding]:
        return sorted(
            findings,
            key=lambda f: (
                f.severity.rank,
                f.confidence.rank,
                f.relative_path.lower(),
                f.line_number,
                f.pattern_name,
            ),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _relative_posix(path: Path, base: Path) -> str:
    try:
        rel = path.relative_to(base)
    except ValueError:
        return path.as_posix()
    rel_str = rel.as_posix()
    return "" if rel_str in ("", ".") else rel_str


def _decode(data: bytes) -> str:
    for enc in ENCODING_FALLBACKS:
        if enc == "utf-16" and not (data[:2] in (b"\xff\xfe", b"\xfe\xff")):
            continue
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, ValueError):
            continue
    return data.decode("latin-1", errors="replace")


def _dedupe_matches(matches: list[RawMatch]) -> list[RawMatch]:
    """Resolve overlapping matches so the most specific pattern wins."""
    ordered = sorted(
        matches,
        key=lambda m: (
            m.detector.severity.rank,
            -m.weight,
            m.start,
            -(m.end - m.start),
        ),
    )
    kept: list[RawMatch] = []
    for m in ordered:
        overlaps = any(
            m.start < kept_end and m.end > kept_start
            for kept_start, kept_end, _w in [(k.start, k.end, k.weight) for k in kept]
        )
        if overlaps:
            continue
        kept.append(m)
    return kept


class _ZipWorkspace:
    """Extract a ZIP into a temp dir; clean up afterwards."""

    def __init__(self, zip_path: str) -> None:
        self.zip_path = zip_path
        self.path: Path = None  # type: ignore[assignment]

    def __enter__(self) -> "_ZipWorkspace":
        base = tempfile.mkdtemp(prefix="secretsentry-zip-")
        self.path = Path(base)
        with zipfile.ZipFile(self.zip_path) as zf:
            for member in zf.infolist():
                target = self._safe_target(member.filename)
                if target is None:
                    continue
                full = self.path / target
                if member.is_dir():
                    full.mkdir(parents=True, exist_ok=True)
                    continue
                full.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(full, "wb") as dst:
                    shutil.copyfileobj(src, dst)
        return self

    def __exit__(self, *exc) -> None:
        shutil.rmtree(self.path, ignore_errors=True)

    @staticmethod
    def _safe_target(name: str) -> Optional[str]:
        cleaned = name.replace("\\", "/")
        parts = [p for p in cleaned.split("/") if p not in ("", ".", "..")]
        if not parts:
            return None
        return "/".join(parts)


def detect_source_type(source: str) -> str:
    return ScanEngine._detect_source_type(source)