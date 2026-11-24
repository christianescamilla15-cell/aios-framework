"""Changelog — auto-generate before/after diffs and maintain history."""
from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List


def generate_changelog(root: Path, commits: int = 1) -> Dict:
    """Generate changelog from recent commits."""
    entries = []

    try:
        # Get recent commits
        log_result = subprocess.run(
            ["git", "log", f"--max-count={commits}", "--pretty=format:%H|%s|%ai"],
            cwd=str(root), capture_output=True, text=True, timeout=5
        )

        for line in log_result.stdout.strip().split("\n"):
            if not line or "|" not in line:
                continue
            parts = line.split("|", 2)
            if len(parts) < 3:
                continue
            sha, message, date = parts

            # Get changed files
            diff_result = subprocess.run(
                ["git", "diff", "--name-status", f"{sha}~1", sha],
                cwd=str(root), capture_output=True, text=True, timeout=5
            )

            files = []
            for fl in diff_result.stdout.strip().split("\n"):
                if fl and "\t" in fl:
                    status, filepath = fl.split("\t", 1)
                    files.append({"status": status[0], "file": filepath})

            # Get diff summary
            stat_result = subprocess.run(
                ["git", "diff", "--stat", f"{sha}~1", sha],
                cwd=str(root), capture_output=True, text=True, timeout=5
            )
            stat = stat_result.stdout.strip().split("\n")[-1] if stat_result.stdout.strip() else ""

            entries.append({
                "sha": sha[:8],
                "message": message,
                "date": date[:10],
                "files": files,
                "stat": stat,
            })

    except Exception:
        pass

    return {"entries": entries, "total": len(entries)}


def generate_diff_report(root: Path, commits: int = 1) -> str:
    """Generate a formatted before/after diff report."""
    try:
        result = subprocess.run(
            ["git", "diff", f"HEAD~{commits}", "--stat"],
            cwd=str(root), capture_output=True, text=True, timeout=5
        )
        stat = result.stdout.strip()

        # Get actual diffs for code files only
        diff_result = subprocess.run(
            ["git", "diff", f"HEAD~{commits}", "--", "*.py", "*.js", "*.jsx", "*.ts"],
            cwd=str(root), capture_output=True, text=True, timeout=10
        )
        diff = diff_result.stdout[:5000]  # Limit to 5KB

        return f"## Changes (last {commits} commits)\n\n```\n{stat}\n```\n\n## Diff\n\n```diff\n{diff}\n```"
    except Exception as e:
        return f"Error generating diff: {e}"


def save_changelog(root: Path, commits: int = 3) -> Path:
    """Save changelog to docs/CHANGELOG.md."""
    data = generate_changelog(root, commits)
    diff_report = generate_diff_report(root, commits)

    content = f"# Changelog\n\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"

    for entry in data["entries"]:
        content += f"## [{entry['sha']}] {entry['message']}\n"
        content += f"Date: {entry['date']}\n\n"

        added = [f["file"] for f in entry["files"] if f["status"] == "A"]
        modified = [f["file"] for f in entry["files"] if f["status"] == "M"]
        deleted = [f["file"] for f in entry["files"] if f["status"] == "D"]

        if added:
            content += f"### Added\n" + "".join(f"- {f}\n" for f in added) + "\n"
        if modified:
            content += f"### Modified\n" + "".join(f"- {f}\n" for f in modified) + "\n"
        if deleted:
            content += f"### Deleted\n" + "".join(f"- {f}\n" for f in deleted) + "\n"

        content += f"{entry['stat']}\n\n---\n\n"

    content += diff_report

    path = root / "docs" / "CHANGELOG.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def clear_changelog(root: Path) -> bool:
    """Remove changelog to free memory."""
    path = root / "docs" / "CHANGELOG.md"
    if path.exists():
        path.unlink()
        return True
    return False


def get_changelog_size(root: Path) -> int:
    """Get changelog file size in KB."""
    path = root / "docs" / "CHANGELOG.md"
    if path.exists():
        return round(path.stat().st_size / 1024, 1)
    return 0
