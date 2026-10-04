"""Exclusion rules: default noise + gitignore-style matching + .cyberignore.

Pattern semantics follow gitignore closely:

* ``#`` starts a comment
* ``!`` negates a rule (re-include)
* trailing ``/`` means "directory only"
* a ``/`` anywhere else anchors the rule to its base directory
* ``**`` matches across path separators, ``*`` within a segment
* ``?`` matches a single character (not a separator)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath


DEFAULT_DIRS = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", "bower_components", "vendor",
    "__pycache__", ".venv", "venv", "env",
    "dist", "build", "out", "coverage", ".next", ".nuxt",
    ".cache", ".idea", ".vscode", ".tox", ".eggs", "target",
    "site-packages", ".gradle", ".mypy_cache", ".pytest_cache", ".ruff_cache",
})

DEFAULT_PATTERNS = frozenset({
    "*.min.js",
    "*.min.css",
    "*.map",
})


@dataclass(frozen=True)
class Rule:
    regex: "re.Pattern[str]"
    negated: bool
    dir_only: bool


def _segment_glob_to_regex(pattern: str) -> str:
    """Translate a single path segment glob into an inline regex fragment."""
    out: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        elif ch == "[":
            j = pattern.find("]", i + 1)
            if j == -1:
                out.append(re.escape(ch))
            else:
                inner = pattern[i + 1 : j]
                if inner.startswith("!"):
                    inner = "^" + inner[1:]
                out.append("[" + inner.replace("\\", "\\\\") + "]")
                i = j
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


def _compile_pattern(pattern: str) -> re.Pattern[str]:
    pattern = pattern.rstrip()
    # Leading/trailing slashes are irrelevant for matching.
    pattern = pattern.strip("/")
    if "/" not in pattern:
        # Match the name at any depth, or the path under it.
        seg = _segment_glob_to_regex(pattern)
        return re.compile(r"(?:^|/)" + seg + r"(?:/.*)?$")
    if pattern.startswith("**/"):
        rest = pattern[3:]
        seg = _segment_glob_to_regex(rest)
        return re.compile(r"(?:.*/)?" + seg + r"(?:/.*)?$")
    parts = pattern.split("/")
    compiled = "/".join(_segment_glob_to_regex(p) for p in parts)
    return re.compile(r"^" + compiled + r"(?:/.*)?$")


def parse_gitignore_line(line: str) -> Rule | None:
    line = line.rstrip("\r\n")
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    negated = stripped.startswith("!")
    if negated:
        pattern = stripped[1:].strip()
    else:
        pattern = stripped
    if not pattern:
        return None
    dir_only = pattern.endswith("/")
    if dir_only:
        pattern = pattern.rstrip("/")
    return Rule(_compile_pattern(pattern), negated, dir_only)


def _rules_from_lines(lines: list[str], negatable: bool = True) -> list[Rule]:
    rules: list[Rule] = []
    for line in lines:
        rule = parse_gitignore_line(line)
        if rule is not None:
            if rule.negated and not negatable:
                continue
            rules.append(rule)
    return rules


class IgnoreMatcher:
    """Evaluates a stack of ignore rule sets. Later rules win over earlier ones."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []

    def add_defaults(self) -> None:
        dir_rules: list[Rule] = []
        for name in sorted(DEFAULT_DIRS):
            pattern = re.escape(name)
            dir_rules.append(Rule(re.compile(r"(?:^|/)" + pattern + r"(?:/.*)?$"), False, True))
        self._rules.extend(dir_rules)
        # Glob patterns apply to files (and any matching names).
        self._rules.extend(_rules_from_lines(sorted(DEFAULT_PATTERNS)))

    def add_text(self, text: str) -> None:
        self._rules.extend(_rules_from_lines(text.splitlines()))

    def add_patterns(self, patterns: list[str]) -> None:
        self._rules.extend(_rules_from_lines(patterns))

    @property
    def has_negation(self) -> bool:
        return any(r.negated for r in self._rules)

    def ignored(self, rel_path: str, *, is_dir: bool = False) -> bool:
        """Return True when the relative (POSIX) path is ignored.

        ``rel_path`` should be relative to the scan root.
        """
        rel_path = rel_path.replace("\\", "/")
        result = False
        for rule in self._rules:
            # A "directory only" rule only excludes directories (and their
            # contents, handled by the ancestor check below).
            target = rel_path + "/" if (rule.dir_only and not is_dir) else rel_path
            if rule.regex.match(target) is None:
                continue
            result = not rule.negated
        # Files inside an ignored directory are ignored too, even when their own
        # name matches no rule (gitignore semantics).
        if not result and not is_dir:
            pure = PurePosixPath(rel_path)
            for _ in range(len(pure.parts) - 1):
                pure = pure.parent
                if self._dir_ignored(pure.as_posix()):
                    result = True
                    break
        return result

    def _dir_ignored(self, rel_dir: str) -> bool:
        """True when a directory is excluded by a rule.

        Only the directory path is tested (without a trailing slash) so globs like
        ``ignored/*`` never match the ``ignored`` directory itself.
        """
        rel_dir = rel_dir.replace("\\", "/")
        result = False
        for rule in self._rules:
            if rule.regex.match(rel_dir):
                result = not rule.negated
        return result


def load_ignore_rules(scan_root) -> IgnoreMatcher:
    """Build a matcher from defaults + ``.gitignore`` + ``.cyberignore`` in the root."""
    matcher = IgnoreMatcher()
    matcher.add_defaults()

    root = scan_root
    gitignore = root / ".gitignore"
    if gitignore.is_file():
        try:
            matcher.add_text(gitignore.read_text(encoding="utf-8-sig", errors="replace"))
        except OSError:
            pass

    cyberignore = root / ".cyberignore"
    if cyberignore.is_file():
        try:
            matcher.add_text(cyberignore.read_text(encoding="utf-8-sig", errors="replace"))
        except OSError:
            pass

    return matcher