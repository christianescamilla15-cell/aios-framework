"""Memory Engine — persistent project context management."""
from __future__ import annotations

from pathlib import Path
from typing import Dict


MEMORY_DEFAULTS: Dict[str, str] = {
    "product_context.md": "# Product Context\n\nDescribe the product, users, and critical workflows.\n",
    "tech_context.md": "# Tech Context\n\nDescribe the stack, tooling, and infrastructure.\n",
    "architecture_context.md": "# Architecture Context\n\nDescribe modules, services, and dependencies.\n",
    "active_workstream.md": "# Active Workstream\n\nNo active workstream yet.\n",
    "recent_decisions.md": "# Recent Decisions\n\n",
    "known_risks.md": "# Known Risks\n\n",
}


def ensure_memory(root: Path) -> int:
    """Create memory directory and default files. Returns count of new files created."""
    memory_dir = root / "ai-memory"
    memory_dir.mkdir(parents=True, exist_ok=True)
    created = 0
    for name, content in MEMORY_DEFAULTS.items():
        path = memory_dir / name
        if not path.exists():
            path.write_text(content, encoding="utf-8")
            created += 1
    return created


def read_memory(root: Path) -> Dict[str, str]:
    """Read all memory files into a dict."""
    memory_dir = root / "ai-memory"
    result = {}
    if memory_dir.exists():
        for f in memory_dir.glob("*.md"):
            result[f.name] = f.read_text(encoding="utf-8")
    return result


def update_workstream(root: Path, task: str, mode: str, spec_path: str, phase: str = "Context Discovery", summary: str = "", next_step: str = "") -> None:
    """Update active workstream."""
    content = f"""# Active Workstream

## Current Task
{task}

## Mode
{mode}

## Active Spec
{spec_path}

## Current Phase
{phase}

## Session Summary
{summary}

## Next Step
{next_step or "Fill spec files, then run execution prompt."}
"""
    (root / "ai-memory" / "active_workstream.md").write_text(content, encoding="utf-8")


def append_decision(root: Path, entry: str) -> None:
    """Append to recent_decisions.md."""
    path = root / "ai-memory" / "recent_decisions.md"
    existing = path.read_text(encoding="utf-8") if path.exists() else "# Recent Decisions\n\n"
    path.write_text(existing + f"\n{entry}\n", encoding="utf-8")


def append_risk(root: Path, entry: str) -> None:
    """Append to known_risks.md."""
    path = root / "ai-memory" / "known_risks.md"
    existing = path.read_text(encoding="utf-8") if path.exists() else "# Known Risks\n\n"
    path.write_text(existing + f"\n{entry}\n", encoding="utf-8")


def get_active_task(root: Path) -> Dict[str, str]:
    """Parse active workstream and return current state."""
    path = root / "ai-memory" / "active_workstream.md"
    if not path.exists():
        return {"task": "", "mode": "", "spec": "", "phase": ""}

    content = path.read_text(encoding="utf-8")
    result = {}
    lines = content.splitlines()
    for i, line in enumerate(lines):
        s = line.strip()
        if s == "## Current Task" and i + 1 < len(lines):
            result["task"] = lines[i + 1].strip()
        elif s == "## Mode" and i + 1 < len(lines):
            result["mode"] = lines[i + 1].strip()
        elif s == "## Active Spec" and i + 1 < len(lines):
            result["spec"] = lines[i + 1].strip()
        elif s == "## Current Phase" and i + 1 < len(lines):
            result["phase"] = lines[i + 1].strip()
    return result
