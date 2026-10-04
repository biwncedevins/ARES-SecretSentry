"""Central configuration for SecretSentry."""

from __future__ import annotations

DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB

# Maximum number of generic high-entropy findings to keep before giving up.
# Prevents huge noise from minified/generated files without losing the signal.
MAX_GENERIC_FINDINGS = 1000

# Cap on how many findings fit in a single line preview (context snippet).
CONTEXT_MAX_CHARS = 200

# Text encodings tried, in order, when decoding scanned files.
ENCODING_FALLBACKS = ("utf-8-sig", "utf-16", "latin-1")

# Auto-skip known binary (non-text) extensions.
BINARY_EXTENSIONS = {
    ".a", ".avif", ".bin", ".bmp", ".bz2", ".class", ".cur", ".db", ".dll",
    ".doc", ".docx", ".exe", ".flac", ".gif", ".gz", ".ico", ".jar", ".jpeg",
    ".jpg", ".lib", ".lnk", ".m4a", ".m4v", ".mov", ".mp3", ".mp4", ".msi",
    ".o", ".obj", ".odp", ".ods", ".odt", ".ogg", ".otf", ".pdf", ".pdb",
    ".png", ".ppt", ".pptx", ".psd", ".pyc", ".pyo", ".rar", ".so", ".sqlite",
    ".sqlite3", ".tar", ".tif", ".tiff", ".ttf", ".wav", ".wasm", ".webm",
    ".webp", ".woff", ".woff2", ".xls", ".xlsx", ".xz", ".zip", ".zst",
}

# Source types accepted by the scanner.
SOURCE_FOLDER = "folder"
SOURCE_ZIP = "zip"
SOURCE_GIT = "git"