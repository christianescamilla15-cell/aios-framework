"""Release Gate — validates readiness before deployment."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from .memory_engine import get_active_task, read_memory


def check_release_readiness(root: Path) -> Dict:
    """Run release gate checks and return results."""
    checks: List[Dict] = []
    blocking = False

    # 1. Active task exists
    task = get_active_task(root)
    if task.get("task"):
        checks.append({"check": "Active task defined", "status": "pass", "detail": task["task"]})
    else:
        checks.append({"check": "Active task defined", "status": "fail", "detail": "No active workstream"})
        blocking = True

    # 2. Spec exists
    spec_path = task.get("spec", "")
    if spec_path and Path(spec_path).exists():
        checks.append({"check": "Spec folder exists", "status": "pass", "detail": spec_path})
    else:
        checks.append({"check": "Spec folder exists", "status": "fail", "detail": "Missing spec"})
        blocking = True

    # 3. Tasks.md has content
    if spec_path:
        tasks_file = Path(spec_path) / "tasks.md"
        if tasks_file.exists() and len(tasks_file.read_text(encoding="utf-8")) > 50:
            checks.append({"check": "Tasks defined", "status": "pass"})
        else:
            checks.append({"check": "Tasks defined", "status": "warn", "detail": "tasks.md empty or missing"})

    # 4. Validation.md exists
    if spec_path:
        val_file = Path(spec_path) / "validation.md"
        if val_file.exists() and len(val_file.read_text(encoding="utf-8")) > 50:
            checks.append({"check": "Validation criteria defined", "status": "pass"})
        else:
            checks.append({"check": "Validation criteria defined", "status": "warn", "detail": "validation.md empty"})

    # 5. Risks reviewed
    memory = read_memory(root)
    risks_content = memory.get("known_risks.md", "")
    if len(risks_content) > 30:
        checks.append({"check": "Risks documented", "status": "pass"})
    else:
        checks.append({"check": "Risks documented", "status": "warn", "detail": "No risks documented"})

    # 6. Rollback plan (for migration/feature)
    mode = task.get("mode", "")
    if mode in ("MIGRATION", "FEATURE", "LEGACY_MODERNIZATION") and spec_path:
        rb_file = Path(spec_path) / "rollback.md"
        if rb_file.exists() and len(rb_file.read_text(encoding="utf-8")) > 50:
            checks.append({"check": "Rollback plan defined", "status": "pass"})
        else:
            checks.append({"check": "Rollback plan defined", "status": "warn", "detail": "rollback.md empty"})

    passed = sum(1 for c in checks if c["status"] == "pass")
    warned = sum(1 for c in checks if c["status"] == "warn")
    failed = sum(1 for c in checks if c["status"] == "fail")

    return {
        "ready": not blocking and failed == 0,
        "passed": passed,
        "warned": warned,
        "failed": failed,
        "total": len(checks),
        "checks": checks,
        "blocking": blocking,
    }
