"""Cache — stores analysis results to avoid re-scanning unchanged repos."""
from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional


CACHE_DIR = ".aios/cache"
CACHE_TTL = 300  # 5 minutes


def _get_cache_path(root: Path, key: str) -> Path:
    path = root / CACHE_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path / f"{key}.json"


def _get_repo_hash(root: Path) -> str:
    """Fast hash of repo state using git."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(root),
            capture_output=True, text=True, timeout=3
        )
        head = result.stdout.strip() if result.returncode == 0 else ""

        result2 = subprocess.run(
            ["git", "diff", "--stat"], cwd=str(root),
            capture_output=True, text=True, timeout=3
        )
        diff_stat = result2.stdout.strip() if result2.returncode == 0 else ""

        return hashlib.md5(f"{head}:{diff_stat}".encode()).hexdigest()[:12]
    except Exception:
        return str(int(time.time()))


def get_cache(root: Path, key: str) -> Optional[Dict]:
    """Get cached result if still valid."""
    path = _get_cache_path(root, key)
    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        # Check TTL
        if time.time() - data.get("_timestamp", 0) > CACHE_TTL:
            return None
        # Check repo hasn't changed
        if data.get("_repo_hash") != _get_repo_hash(root):
            return None
        return data.get("_result")
    except Exception:
        return None


def set_cache(root: Path, key: str, result: Any) -> None:
    """Cache a result."""
    path = _get_cache_path(root, key)
    try:
        data = {
            "_timestamp": time.time(),
            "_repo_hash": _get_repo_hash(root),
            "_result": result,
        }
        path.write_text(json.dumps(data, default=str), encoding="utf-8")
    except Exception:
        pass


def invalidate_cache(root: Path) -> None:
    """Clear all cached results."""
    cache_dir = root / CACHE_DIR
    if cache_dir.exists():
        for f in cache_dir.glob("*.json"):
            f.unlink()
