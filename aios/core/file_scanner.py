"""File Scanner — respects .gitignore, excludes noise directories."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List, Set

EXCLUDE_DIRS: Set[str] = {
    "node_modules", ".git", "dist", "build", "__pycache__", ".next",
    ".venv", "venv", "env", ".env", ".cache", ".aios", "coverage",
    ".nyc_output", ".pytest_cache", ".mypy_cache", ".tox",
    "vendor", "bower_components", "jspm_packages",
    ".wwebjs_auth", ".wwebjs_cache", "wa_session", "auth_info",
}

EXCLUDE_EXTENSIONS: Set[str] = {
    ".pyc", ".pyo", ".exe", ".dll", ".so", ".dylib",
    ".wasm", ".map", ".min.js", ".min.css",
    ".lock", ".log",
}


def scan_tracked_files(root: Path) -> List[str]:
    """Get files tracked by git (respects .gitignore)."""
    try:
        result = subprocess.run(
            ["git", "ls-files"], cwd=str(root),
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return [f for f in result.stdout.strip().split("\n") if f and not _is_excluded(f)]
    except Exception:
        pass
    # Fallback: manual scan with exclusions
    return scan_with_exclusions(root)


def scan_with_exclusions(root: Path, max_files: int = 5000) -> List[str]:
    """Scan files manually, excluding noise directories."""
    files = []
    for f in root.rglob("*"):
        if len(files) >= max_files:
            break
        if not f.is_file():
            continue
        rel = str(f.relative_to(root))
        if not _is_excluded(rel):
            files.append(rel)
    return files


def _is_excluded(filepath: str) -> bool:
    """Check if file should be excluded."""
    parts = filepath.replace("\\", "/").split("/")
    # Check directory exclusions
    for part in parts[:-1]:
        if part in EXCLUDE_DIRS:
            return True
    # Check extension exclusions
    for ext in EXCLUDE_EXTENSIONS:
        if filepath.endswith(ext):
            return True
    return False


def scan_source_files(root: Path, extensions: List[str] | None = None) -> List[Path]:
    """Scan only source code files (no binaries, no dependencies)."""
    exts = extensions or [".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rs"]
    files = scan_tracked_files(root)
    return [root / f for f in files if any(f.endswith(e) for e in exts)]
