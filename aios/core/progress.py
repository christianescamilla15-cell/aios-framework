"""Migration/Task Progress Tracking — tracks % completion across specs."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List


def track_progress(root: Path) -> Dict:
    """Track progress across all specs."""
    specs_dir = root / "specs"
    if not specs_dir.exists():
        return {"specs": [], "overall": 0}

    specs = []
    total_tasks = 0
    completed_tasks = 0

    for spec_dir in sorted(specs_dir.iterdir()):
        if not spec_dir.is_dir():
            continue

        tasks_file = spec_dir / "tasks.md"
        validation_file = spec_dir / "validation.md"

        spec_info = {
            "name": spec_dir.name,
            "mode": spec_dir.name.split("-")[0] if "-" in spec_dir.name else "unknown",
            "tasks_total": 0,
            "tasks_completed": 0,
            "has_design": (spec_dir / "design.md").exists(),
            "has_validation": validation_file.exists(),
            "has_rollback": (spec_dir / "rollback.md").exists(),
            "checklist_done": 0,
            "checklist_total": 0,
        }

        # Count tasks
        if tasks_file.exists():
            content = tasks_file.read_text(encoding="utf-8", errors="ignore")
            spec_info["tasks_total"] = len(re.findall(r"^### T\d", content, re.MULTILINE))
            # Tasks with "DONE" or "completed" or checked checkbox
            spec_info["tasks_completed"] = len(re.findall(r"- \[x\]|DONE|completed|COMPLETED", content, re.IGNORECASE))

        # Count validation checklist
        if validation_file.exists():
            content = validation_file.read_text(encoding="utf-8", errors="ignore")
            spec_info["checklist_total"] = content.count("- [ ]") + content.count("- [x]")
            spec_info["checklist_done"] = content.count("- [x]")

        # Calculate completion %
        divisor = max(spec_info["tasks_total"], 1)
        spec_info["completion"] = round(spec_info["tasks_completed"] / divisor * 100)

        total_tasks += spec_info["tasks_total"]
        completed_tasks += spec_info["tasks_completed"]
        specs.append(spec_info)

    overall = round(completed_tasks / max(total_tasks, 1) * 100)

    return {
        "specs": specs,
        "total_tasks": total_tasks,
        "completed_tasks": completed_tasks,
        "overall": overall,
    }
