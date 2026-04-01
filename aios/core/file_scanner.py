"""File Scanner — respects .gitignore + .aiosignore, parallel processing, caching."""
from __future__ import annotations

import fnmatch
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Set, Callable

from .cache import get_cache, set_cache

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


def _load_aiosignore(root: Path) -> List[str]:
    """Load custom exclusion patterns from .aiosignore."""
    ignore_file = root / ".aiosignore"
    if not ignore_file.exists():
        return []
    patterns = []
    for line in ignore_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def _is_excluded(filepath: str, custom_patterns: List[str] | None = None) -> bool:
    """Check if file should be excluded."""
    parts = filepath.replace("\\", "/").split("/")
    # Directory exclusions
    for part in parts[:-1]:
        if part in EXCLUDE_DIRS:
            return True
    # Extension exclusions
    for ext in EXCLUDE_EXTENSIONS:
        if filepath.endswith(ext):
            return True
    # Custom .aiosignore patterns
    if custom_patterns:
        for pattern in custom_patterns:
            if fnmatch.fnmatch(filepath, pattern) or fnmatch.fnmatch(parts[-1], pattern):
                return True
            # Directory pattern (e.g., "generated/")
            if pattern.endswith("/") and any(part == pattern.rstrip("/") for part in parts):
                return True
    return False


def scan_tracked_files(root: Path, service: str | None = None) -> List[str]:
    """Get files tracked by git (respects .gitignore + .aiosignore).

    Args:
        root: project root
        service: optional service name for monorepo partitioning
    """
    # Check cache first
    cache_key = f"files_{service or 'all'}"
    cached = get_cache(root, cache_key)
    if cached is not None:
        return cached

    custom_patterns = _load_aiosignore(root)

    try:
        result = subprocess.run(
            ["git", "ls-files"], cwd=str(root),
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0 and result.stdout.strip():
            files = [f for f in result.stdout.strip().split("\n")
                     if f and not _is_excluded(f, custom_patterns)]
            # Partition by service if requested
            if service:
                files = [f for f in files if f.startswith(f"{service}/") or f.startswith(f"{service}\\")]
            set_cache(root, cache_key, files)
            return files
    except Exception:
        pass

    files = scan_with_exclusions(root, custom_patterns=custom_patterns)
    if service:
        files = [f for f in files if f.startswith(f"{service}/")]
    set_cache(root, cache_key, files)
    return files


def scan_with_exclusions(root: Path, max_files: int = 10000, custom_patterns: List[str] | None = None) -> List[str]:
    """Scan files manually with exclusions."""
    files = []
    for f in root.rglob("*"):
        if len(files) >= max_files:
            break
        if not f.is_file():
            continue
        rel = str(f.relative_to(root)).replace("\\", "/")
        if not _is_excluded(rel, custom_patterns):
            files.append(rel)
    return files


def scan_source_files(root: Path, extensions: List[str] | None = None, service: str | None = None) -> List[Path]:
    """Scan only source code files."""
    exts = extensions or [".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rs"]
    files = scan_tracked_files(root, service=service)
    return [root / f for f in files if any(f.endswith(e) for e in exts)]


def parallel_scan(root: Path, processor: Callable, files: List[Path], max_workers: int = 8) -> List:
    """Process files in parallel using thread pool."""
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(processor, f): f for f in files}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    results.append(result)
            except Exception:
                pass
    return results
