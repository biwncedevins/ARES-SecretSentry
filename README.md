# SecretSentry

A fast, offline-first Windows desktop security tool for developers. Scan a folder,
ZIP archive, or Git working tree for accidentally exposed secrets **before** you
push to GitHub or share it publicly.

No data ever leaves your machine. Scanned files, findings, and secrets are never
sent anywhere.

## Features

- **Offline-first** – everything runs locally.
- **Fast scans** – skips `.git`, `node_modules`, `vendor`, binaries, and large files
  by default.
- **Smart detection** – a mix of precise regex detectors **plus** entropy analysis.
  Not entropy alone, so false positives stay low.
- **Easy to extend** – add new detectors as small declarative rules.
- **`.cyberignore` support** – your own exclusion rules (gitignore-style).
- **Great UX** – clean, professional developer-tool look. No hacker theatrics.
- **Safe exports** – JSON/CSV reports never contain raw secrets. Everything is
  redacted.

## Installation

```bash
pip install -r requirements.txt
python main.py
```

Requires **Python 3.11+** and **PySide6**.

## Quick start

1. Pick **Folder**, **ZIP**, or **Git working tree**.
2. Hit **Start scan**.
3. Review findings in the table; select one to see the redacted detail.
4. Export a **JSON** or **CSV** report from the **Report** tab.

## Detection pipeline

```
SELECT → IGNORE → DETECT → ENTROPY → DEDUPE → REDACT → REPORT
```

- **SELECT** folder, ZIP archive, or Git working tree.
- **IGNORE** default noise (`.git`, `node_modules`, `vendor`, binaries, big files)
  and your `.cyberignore` patterns.
- **DETECT** known secret formats via detector patterns.
- **ENTROPY** confirms random-looking secrets and flags unknown high-entropy strings.
- **DEDUPE** overlapping matches resolve to the most specific pattern; identical
  secrets are merged with an occurrence count.
- **REDACT** every preview masks the secret before it reaches the UI or a report.
- **REPORT** exports safe JSON/CSV summaries with metadata.

## Ignoring files

SecretSentry skips these by default:

```
.git, .hg, .svn, node_modules, vendor, __pycache__, .venv, venv,
dist, build, coverage, .idea, .vscode, .next, .cache, target,
*.min.js, *.min.css, *.map
```

Create a `.cyberignore` file in the scanned root to add your own rules. It uses
gitignore syntax: `#` comments, `!` to re-include, `/` to anchor, `**` for paths,
trailing `/` for directories.

```gitignore
# .cyberignore example
**/*.generated.ts
keys-local/
secrets/*.txt
!secrets/README.md
```

If you scan a Git working tree, the repository's `.gitignore` is respected too.

## Adding a detector

Detectors live in `secretsentry/detectors.py`. Add a line to register a new
pattern:

```python
detector(
    id="my_service_key",
    name="MyService API Key",
    category="Cloud Credentials",
    severity=Severity.HIGH,
    patterns=(("\\bmsc_[A-Za-z0-9]{32}\\b", 0),),
)
```

`patterns` are `(regex, value_group)` tuples. Set `min_entropy` to require
random-looking values, `confidence` to tune trust, and `weight` for dedupe
priority (higher = wins overlaps).

## Reports

- **SecretsSentry never writes raw secrets to exports or logs.**
- JSON report includes scan metadata, severity breakdowns, and redacted findings.
- CSV report is the same information flattened into rows.

## Architecture

```
main.py                  entry point
secretsentry/
  models.py              Finding / Severity / Confidence / ScanResult
  entropy.py             Shannon entropy analysis
  redact.py              safe redaction helpers
  ignore.py              gitignore-style matcher + defaults
  detectors.py           detector registry + built-in patterns
  scanner.py             scan engine (the pipeline)
  reporting.py           JSON/CSV export
  ui/
    theme.py             colors + QSS stylesheet
    widgets.py           shared UI building blocks
    worker.py            background scan thread
    main_window.py       window + navigation
    dashboard.py         source selection + progress
    results.py           findings table + filters + details
    report_page.py       summary + export
```