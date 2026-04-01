"""Kiro Bridge — integration between AIOS CLI and Kiro IDE / Claude Code."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, List


def generate_kiro_steering(root: Path) -> Path:
    """Generate .kiro/steering/ files from AIOS ai-system/ files."""
    src = root / "ai-system"
    dst = root / ".kiro" / "steering"
    dst.mkdir(parents=True, exist_ok=True)

    copied = 0
    if src.exists():
        for f in src.glob("*.md"):
            target = dst / f.name
            if not target.exists():
                target.write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
                copied += 1

    return dst


def generate_kiro_specs(root: Path) -> Path:
    """Ensure .kiro/specs/ mirrors AIOS specs/."""
    src = root / "specs"
    dst = root / ".kiro" / "specs"
    dst.mkdir(parents=True, exist_ok=True)

    if src.exists():
        for spec_dir in src.iterdir():
            if spec_dir.is_dir():
                target = dst / spec_dir.name
                target.mkdir(exist_ok=True)
                for f in spec_dir.glob("*.md"):
                    target_file = target / f.name
                    if not target_file.exists():
                        target_file.write_text(f.read_text(encoding="utf-8"), encoding="utf-8")

    return dst


def sync_to_kiro(root: Path) -> Dict:
    """Full sync AIOS → Kiro directory structure."""
    steering = generate_kiro_steering(root)
    specs = generate_kiro_specs(root)

    # Count
    steering_count = len(list(steering.glob("*.md"))) if steering.exists() else 0
    specs_count = len(list(specs.iterdir())) if specs.exists() else 0

    return {
        "steering_path": str(steering),
        "steering_files": steering_count,
        "specs_path": str(specs),
        "specs_count": specs_count,
    }


def search_codebase(root: Path, query: str, max_results: int = 20) -> List[Dict]:
    """Simple codebase search using grep (placeholder for vector search)."""
    try:
        result = subprocess.run(
            ["git", "grep", "-n", "-i", "--max-count=3", query],
            cwd=str(root), capture_output=True, text=True, timeout=10
        )
        matches = []
        for line in result.stdout.strip().split("\n")[:max_results]:
            if ":" in line:
                parts = line.split(":", 2)
                if len(parts) >= 3:
                    matches.append({"file": parts[0], "line": parts[1], "content": parts[2][:100]})
        return matches
    except Exception:
        return []
