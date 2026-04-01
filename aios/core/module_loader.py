"""Module Loader — loads and runs stack-specific checks."""
from __future__ import annotations

import importlib
from pathlib import Path
from typing import Dict, List

AVAILABLE_STACKS = ["multiagent", "python", "cicd", "react", "aws", "docker"]


def get_stack_info(stack_id: str) -> Dict:
    """Get stack metadata."""
    try:
        mod = importlib.import_module(f"aios.stacks.{stack_id}")
        return {"id": getattr(mod, "STACK_ID", stack_id), "name": getattr(mod, "STACK_NAME", stack_id)}
    except ImportError:
        return {"id": stack_id, "name": stack_id}


def list_stacks() -> List[Dict]:
    """List all available stacks."""
    return [get_stack_info(s) for s in AVAILABLE_STACKS]


def run_stack_checks(stack_id: str, root: Path) -> List[Dict]:
    """Run checks for a specific stack."""
    try:
        mod = importlib.import_module(f"aios.stacks.{stack_id}.checks")
        return mod.run_checks(root)
    except (ImportError, AttributeError) as e:
        return [{"check": f"Stack '{stack_id}' checks", "status": "fail", "detail": str(e)}]


def detect_relevant_stacks(root: Path) -> List[str]:
    """Auto-detect which stacks are relevant for this project."""
    detected = []
    files_str = " ".join(str(f) for f in root.rglob("*") if f.is_file() and ".git" not in str(f))
    files_lower = files_str.lower()

    if "requirements.txt" in files_lower or "pyproject.toml" in files_lower or ".py" in files_lower:
        detected.append("python")
    if "package.json" in files_lower and ("jsx" in files_lower or "tsx" in files_lower):
        detected.append("react")
    if "agent" in files_lower or "orchestrat" in files_lower:
        detected.append("multiagent")
    if "dockerfile" in files_lower or "docker-compose" in files_lower:
        detected.append("docker")
    if ".tf" in files_lower or "aws" in files_lower or "bedrock" in files_lower:
        detected.append("aws")
    if ".github/workflows" in files_lower or "ci" in files_lower:
        detected.append("cicd")

    return detected


def run_all_relevant_checks(root: Path) -> Dict[str, List[Dict]]:
    """Detect stacks and run all relevant checks."""
    stacks = detect_relevant_stacks(root)
    results = {}
    for stack_id in stacks:
        results[stack_id] = run_stack_checks(stack_id, root)
    return results
