"""Shannon entropy analysis used to separate random-looking tokens from real words."""

from __future__ import annotations

import math
import string

_LOWER = set(string.ascii_lowercase)
_UPPER = set(string.ascii_uppercase)
_DIGITS = set(string.digits)
_TOKENS_SYMBOLS = set("_-.+/=")


def shannon_entropy(data: str) -> float:
    """Return the Shannon entropy (bits/char) of a string. 0.0 for empty input."""
    if not data:
        return 0.0
    frequencies: dict[str, int] = {}
    for ch in data:
        frequencies[ch] = frequencies.get(ch, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * (p and math.log2(p))
    return entropy


def distinct_character_classes(data: str) -> int:
    """Count how many of lower/upper/digit/symbol classes appear in the string."""
    classes = 0
    if any(ch in _LOWER for ch in data):
        classes += 1
    if any(ch in _UPPER for ch in data):
        classes += 1
    if any(ch in _DIGITS for ch in data):
        classes += 1
    if any(ch in _TOKENS_SYMBOLS for ch in data):
        classes += 1
    return classes


def looks_random(value: str, *, min_entropy: float = 4.3,
                 min_classes: int = 3) -> bool:
    """Heuristic: high entropy across several character classes looks like a secret."""
    entropy = shannon_entropy(value)
    if entropy < min_entropy:
        return False
    return distinct_character_classes(value) >= min_classes


# Thresholds used by specific detectors.
ENTROPY_STRONG = 4.5
ENTROPY_MODERATE = 3.6
ENTROPY_WEAK = 3.0