"""Release Gate — validates readiness before deployment.

v1.6.0 changes:
- Spec matching by similarity (Jaccard) when active task path missing or stale
- Searches specs/ folder for best match if direct path fails
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from .memory_engine import get_active_task, read_memory


def _tokenize(text: str) -> set:
    """Tokenize text into lowercase word set for similarity."""
    import re
    return set(re.findall(r"\w+", text.lower()))


def _jaccard_similarity(a: str, b: str) -> float:
    """Jaccard similarity between two strings (token-based)."""
    sa, sb = _tokenize(a), _tokenize(b)
    if not sa or not sb:
        return 0.0
    intersection = len(sa & sb)
    union = len(sa | sb)
    return intersection / union if union > 0 else 0.0


def find_spec_by_similarity(root: Path, task_title: str, threshold: float = 0.2) -> Optional[Path]:
    """v1.6.0 NEW · find best matching spec folder for a task title.

    Useful when memory's spec path is stale or task was created without explicit folder.

    Returns: Path to spec folder with highest Jaccard similarity above threshold.
    """
    specs_root = root / "specs"
    if not specs_root.exists():
        return None

    best_match = None
    best_score = 0.0

    for spec_dir in specs_root.iterdir():
        if not spec_dir.is_dir():
            continue
        # Compare slug + first lines of requirements.md
        candidate_text = spec_dir.name
        req_file = spec_dir / "requirements.md"
        if req_file.exists():
            try:
                # First 500 chars of requirements (title + objective usually)
                candidate_text += " " + req_file.read_text(encoding="utf-8")[:500]
            except: pass

        score = _jaccard_similarity(task_title, candidate_text)
        if score > best_score and score >= threshold:
            best_score = score
            best_match = spec_dir

    return best_match


def check_release_readiness(root: Path) -> Dict:
    """Run release gate checks and return results."""
    checks: List[Dict] = []
    blocking = False

    # 1. Active task exists
    task = get_active_task(root)
    task_title = task.get("task", "")
    if task_title:
        checks.append({"check": "Active task defined", "status": "pass", "detail": task_title})
    else:
        checks.append({"check": "Active task defined", "status": "fail", "detail": "No active workstream"})
        blocking = True

    # 2. Spec exists · v1.6.0 fallback to similarity matching
    spec_path = task.get("spec", "")
    spec_dir = None
    if spec_path and Path(spec_path).exists():
        spec_dir = Path(spec_path)
        checks.append({"check": "Spec folder exists", "status": "pass", "detail": spec_path})
    elif task_title:
        # Try similarity matching · v1.6.0
        matched = find_spec_by_similarity(root, task_title)
        if matched:
            spec_dir = matched
            checks.append({
                "check": "Spec folder exists",
                "status": "pass",
                "detail": f"matched by similarity → {matched.name}"
            })
        else:
            checks.append({"check": "Spec folder exists", "status": "fail", "detail": "Missing spec (no match found)"})
            blocking = True
    else:
        checks.append({"check": "Spec folder exists", "status": "fail", "detail": "Missing spec"})
        blocking = True

    # 3. Tasks.md has content
    if spec_dir:
        tasks_file = spec_dir / "tasks.md"
        if tasks_file.exists() and len(tasks_file.read_text(encoding="utf-8")) > 50:
            checks.append({"check": "Tasks defined", "status": "pass"})
        else:
            checks.append({"check": "Tasks defined", "status": "warn", "detail": "tasks.md empty or missing"})

    # 4. Validation.md exists
    if spec_dir:
        val_file = spec_dir / "validation.md"
        if val_file.exists() and len(val_file.read_text(encoding="utf-8")) > 50:
            checks.append({"check": "Validation criteria defined", "status": "pass"})
        else:
            checks.append({"check": "Validation criteria defined", "status": "warn", "detail": "validation.md empty"})

    # 5. Risks reviewed · v1.6.0 also check spec/risks.md
    memory = read_memory(root)
    risks_content = memory.get("known_risks.md", "")
    risks_in_spec = ""
    if spec_dir:
        risks_file = spec_dir / "risks.md"
        if risks_file.exists():
            risks_in_spec = risks_file.read_text(encoding="utf-8")
    if len(risks_content) > 30 or len(risks_in_spec) > 30:
        checks.append({"check": "Risks documented", "status": "pass"})
    else:
        checks.append({"check": "Risks documented", "status": "warn", "detail": "No risks documented"})

    # 6. Rollback plan (for migration/feature/legacy)
    mode = task.get("mode", "")
    if mode in ("MIGRATION", "FEATURE", "LEGACY_MODERNIZATION") and spec_dir:
        rb_file = spec_dir / "rollback.md"
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
