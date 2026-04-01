"""Incremental Analysis — only analyze changed files since last analysis."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Dict, List


def get_changed_files(root: Path, since: str = "HEAD~1") -> List[str]:
    """Get files changed since a reference point."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", since],
            cwd=str(root), capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return [f for f in result.stdout.strip().split("\n") if f]
    except Exception:
        pass

    # Also check staged
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--cached"],
            cwd=str(root), capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            staged = [f for f in result.stdout.strip().split("\n") if f]
            return staged
    except Exception:
        pass

    return []


def get_untracked_files(root: Path) -> List[str]:
    """Get new untracked files."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            cwd=str(root), capture_output=True, text=True, timeout=5
        )
        return [f for f in result.stdout.strip().split("\n") if f]
    except Exception:
        return []


def save_snapshot(root: Path) -> None:
    """Save current file state as snapshot for future incremental comparison."""
    snapshot_path = root / ".aios" / "last_snapshot.json"
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root), capture_output=True, text=True, timeout=5
        )
        commit = result.stdout.strip() if result.returncode == 0 else ""
        snapshot_path.write_text(json.dumps({"commit": commit}), encoding="utf-8")
    except Exception:
        pass


def get_last_snapshot(root: Path) -> str:
    """Get the commit hash from last snapshot."""
    snapshot_path = root / ".aios" / "last_snapshot.json"
    if snapshot_path.exists():
        try:
            data = json.loads(snapshot_path.read_text(encoding="utf-8"))
            return data.get("commit", "HEAD~1")
        except Exception:
            pass
    return "HEAD~1"


def incremental_analyze(root: Path) -> Dict:
    """Analyze only files changed since last snapshot."""
    last_commit = get_last_snapshot(root)
    changed = get_changed_files(root, last_commit)
    untracked = get_untracked_files(root)

    all_changed = list(set(changed + untracked))

    # Categorize
    categories = {"python": [], "javascript": [], "config": [], "infra": [], "test": [], "other": []}
    for f in all_changed:
        fl = f.lower()
        if fl.endswith(".py"):
            categories["python"].append(f)
        elif fl.endswith((".js", ".jsx", ".ts", ".tsx")):
            categories["javascript"].append(f)
        elif fl.endswith((".yml", ".yaml", ".json", ".toml", ".env")):
            categories["config"].append(f)
        elif any(x in fl for x in ["docker", "terraform", ".tf", "k8s", "ci/"]):
            categories["infra"].append(f)
        elif "test" in fl:
            categories["test"].append(f)
        else:
            categories["other"].append(f)

    save_snapshot(root)

    return {
        "total_changed": len(all_changed),
        "since": last_commit[:8] if len(last_commit) > 8 else last_commit,
        "categories": {k: v for k, v in categories.items() if v},
        "files": all_changed,
    }
