"""Tests for the SecretSentry scan engine.

Run with pytest:        python -m pytest tests -q
Run standalone:         python tests/test_engine.py
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from secretsentry.scanner import ScanEngine  # noqa: E402

SAMPLES: dict[str, object] = {
    "app/config.py": (
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
        'password = "sup3rSecretPassw0rd!"\n'
    ),
    "service/.env": (
        "DATABASE_URL=postgres://admin:hunter2@db.example.com:5432/prod\n"
        "GITHUB_TOKEN=ghp_0123456789abcdefghij0123456789abcdefghij\n"
        "SLACK_TOKEN=slack-test-token\n"
    ),
    "certs/server.key": (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA7qCQ4Kd3pKWQ2x4tFbEXvZWcX9J1d2m3nOqH\n"
        "aF8RZfL9nTq3h6sPvYbXcDg5hJk2mNwQ0rM7tU6bGd4eFhS\n"
        "-----END RSA PRIVATE KEY-----\n"
    ),
    "certs/server.pub": (
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7qCQ4Kd3pKWQ2x4tFbEX\n"
        "-----END PUBLIC KEY-----\n"
    ),
    "vendor/lib.js": "var key = 'AKIAIOSFODNN7EXAMPLE';\n",
    "node_modules/pkg/index.js": "console.log('nothing secret');\n",
    "bin/app.exe": b"\x00\x01\x02binary\x00data",
    "big/generated.txt": "x" * (6 * 1024 * 1024),
}


def build_project(root: Path) -> None:
    for name, content in SAMPLES.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(str(content))
    (root / ".cyberignore").write_text("# custom ignore rules\nignored/*\n!ignored/important.txt\n")
    (root / "ignored").mkdir(exist_ok=True)
    (root / "ignored" / "keep.txt").write_text("GITHUB_TOKEN=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")
    (root / "ignored" / "important.txt").write_text("SLACK_TOKEN=slack-test-token\n")


def test_basic_detection_and_ignores() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="secretsentry-test-"))
    try:
        root = tmp / "proj"
        root.mkdir()
        build_project(root)
        engine = ScanEngine()
        result = engine.scan(str(root), source_type="folder")

        ids = {f.pattern_id for f in result.findings}
        assert "aws_access_key" in ids
        assert "aws_secret_access_key" in ids
        assert "credentials_in_url" in ids
        assert "github_token" in ids
        assert "slack_token" in ids
        assert "private_key" in ids
        assert "password_assignment" in ids

        paths = {f.relative_path for f in result.findings}
        assert not any("vendor/" in p for p in paths)
        assert not any("node_modules" in p for p in paths)
        assert not any("big/" in p for p in paths)
        assert not any("bin/" in p for p in paths)
        assert not any("server.pub" in p for p in paths)
        assert any(p == "ignored/important.txt" for p in paths)
        assert not any(p == "ignored/keep.txt" for p in paths)

        # A private key block must not re-flag its base64 body as entropy noise.
        assert result.stats.files_skipped_large >= 1
        assert result.stats.files_skipped_binary >= 1

        # No raw secrets in redacted output.
        fragments = [
            "IOSFODNN7EXAMPLE", "wJalrXUtnFEMI", "hunter2",
            "ghp_0123456789abc", "sup3rSecretPassw0rd",
        ]
        for finding in result.findings:
            for frag in fragments:
                assert frag not in finding.redacted
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_zip_source() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="secretsentry-zip-test-"))
    try:
        zip_path = tmp / "archive.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("src/app.py", "token = 'ghp_0123456789abcdefghij0123456789abcdefghij'\n")
        result = ScanEngine().scan(str(zip_path), source_type="zip")
        assert result.source_type == "zip"
        assert any(f.relative_path == "src/app.py" for f in result.findings)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_gitignore_respected() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="secretsentry-git-test-"))
    try:
        root = tmp / "repo"
        (root / ".git").mkdir(parents=True)
        (root / ".gitignore").write_text("secrets.txt\n")
        (root / "secrets.txt").write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        (root / "app.py").write_text("print('hi')\n")
        result = ScanEngine().scan(str(root), source_type="git")
        assert result.source_type == "git"
        assert all("secrets.txt" not in f.relative_path for f in result.findings)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_dedupe_identical_secret() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="secretsentry-dedupe-"))
    try:
        root = tmp / "proj"
        root.mkdir()
        (root / "a.txt").write_text("KEY=AKIAIOSFODNN7EXAMPLE\nAKIAIOSFODNN7EXAMPLE\n")
        (root / "b.txt").write_text("AKIAIOSFODNN7EXAMPLE\n")
        result = ScanEngine().scan(str(root), source_type="folder")
        aws = [f for f in result.findings if f.pattern_id == "aws_access_key"]
        assert len(aws) == 1
        assert aws[0].occurrences == 3
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_report_no_raw_leaks() -> None:
    from secretsentry.reporting import to_csv, to_json

    tmp = Path(tempfile.mkdtemp(prefix="secretsentry-report-"))
    try:
        root = tmp / "proj"
        root.mkdir()
        (root / "app.txt").write_text(
            "GITHUB_TOKEN=ghp_0123456789abcdefghij0123456789abcdefghij\n"
        )
        result = ScanEngine().scan(str(root), source_type="folder")
        assert result.findings, "expected a finding"
        js = to_json(result)
        csv = to_csv(result)
        assert "ghp_0123456789abcdefghij0123456789abcdefghij" not in js
        assert "ghp_0123456789abcdefghij0123456789abcdefghij" not in csv
        assert "[REDACTED]" in js or "chars hidden" in js or "redacted" in js.lower()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    import traceback

    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS  {name}")
            except Exception:
                failures += 1
                print(f"FAIL  {name}")
                traceback.print_exc()
    if failures:
        raise SystemExit(f"{failures} test(s) failed")
    print("all tests passed")