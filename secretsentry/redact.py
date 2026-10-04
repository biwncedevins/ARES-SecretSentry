"""Safe redaction helpers.

All secret values that reach the UI or an exported report must pass through
:func:`redact_secret`. Raw secrets never leave the scanner engine.
"""

from __future__ import annotations

_MASK = "\u2022"  # bullet character
_HIDDEN_TEXT = "hidden"  # label wording used in redacted previews


def redact_secret(value: str, keep_prefix: int = 4) -> str:
    """Mask a secret, keeping only a short identifying prefix.

    Examples:
        ``AKIAIOSFODNN7EXAMPLE``  -> ``AKIA•••• (17 chars hidden)``
        ``short``                 -> ``•••••``
    """
    if not value:
        return ""
    value = value.strip()
    if len(value) <= keep_prefix:
        return _MASK * len(value)
    head = value[:keep_prefix]
    hidden = len(value) - keep_prefix
    return f"{head}{_MASK * 4} ({hidden} chars hidden)"


def redact_block(value: str, keep_prefix: int = 24) -> str:
    """Redact a multi-line block (e.g. a private key) by showing its first line."""
    heads = [ln.strip() for ln in value.splitlines() if ln.strip()]
    if not heads:
        return _MASK
    first = heads[0]
    if len(first) <= keep_prefix:
        return first
    return first[:keep_prefix] + _MASK * 3 + f" ({len(value)} bytes)"


def mask_line(line: str, spans: list[tuple[int, int]]) -> str:
    """Replace the matched spans of ``line`` with a redaction marker."""
    if not spans:
        return line
    spans = sorted(spans, key=lambda s: s[0])
    parts: list[str] = []
    cursor = 0
    for start, end in spans:
        start = max(start, cursor)
        if start > len(line):
            break
        parts.append(line[cursor:start])
        parts.append("[REDACTED]")
        cursor = max(end, start)
    parts.append(line[cursor:])
    return "".join(parts)


def slice_around(line: str, spans: list[tuple[int, int]], max_chars: int = 200) -> str:
    """Build a short one-line preview centered around the first match."""
    if not spans:
        line = line.strip()
        return line[:max_chars]
    masked = mask_line(line, spans)
    masked = masked.replace("\t", " ").strip()
    if len(masked) <= max_chars:
        return masked
    center = spans[0][0]
    half = max_chars // 2
    start = max(0, center - half)
    snippet = masked[start : start + max_chars]
    prefix = "…" if start > 0 else ""
    suffix = "…" if start + max_chars < len(masked) else ""
    return f"{prefix}{snippet}{suffix}"