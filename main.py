"""SecretSentry entry point.

Usage:
    python main.py
"""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from secretsentry.ui.theme import apply_theme
from secretsentry.ui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("SecretSentry")
    app.setApplicationDisplayName("SecretSentry")
    app.setOrganizationName("SecretSentry")
    apply_theme(app)

    window = MainWindow()
    window.show()

    # Optional: allow scanning a folder straight from the command line.
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if args:
        window.dashboard().set_default_source(args[0])

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())