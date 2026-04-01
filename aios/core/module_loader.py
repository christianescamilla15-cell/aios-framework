"""Module Loader — loads and runs stack-specific checks (optimized)."""
from __future__ import annotations

import importlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List

from .cache import get_cache, set_cache
from .file_scanner import scan_tracked_files

AVAILABLE_STACKS = ["multiagent", "python", "cicd", "react", "aws", "docker"]


def get_stack_info(stack_id: str) -> Dict:
    try:
        mod = importlib.import_module(f"aios.stacks.{stack_id}")
        return {"id": getattr(mod, "STACK_ID", stack_id), "name": getattr(mod, "STACK_NAME", stack_id)}
    except ImportError:
        return {"id": stack_id, "name": stack_id}


def list_stacks() -> List[Dict]:
    return [get_stack_info(s) for s in AVAILABLE_STACKS]


def run_stack_checks(stack_id: str, root: Path) -> List[Dict]:
    """Run checks for a specific stack (with caching)."""
    cache_key = f"checks_{stack_id}"
    cached = get_cache(root, cache_key)
    if cached is not None:
        return cached

    try:
        mod = importlib.import_module(f"aios.stacks.{stack_id}.checks")
        result = mod.run_checks(root)
        set_cache(root, cache_key, result)
        return result
    except (ImportError, AttributeError) as e:
        return [{"check": f"Stack '{stack_id}'", "status": "fail", "detail": str(e)}]


def detect_relevant_stacks(root: Path) -> List[str]:
    """Fast stack detection using git ls-files (not rglob)."""
    cache_key = "detected_stacks"
    cached = get_cache(root, cache_key)
    if cached is not None:
        return cached

    # Use pre-scanned tracked files instead of rglob
    files = scan_tracked_files(root)
    files_lower = " ".join(f.lower() for f in files)

    detected = []
    if "requirements.txt" in files_lower or "pyproject.toml" in files_lower or ".py" in files_lower:
        detected.append("python")
    if "package.json" in files_lower and ("jsx" in files_lower or "tsx" in files_lower):
        detected.append("react")
    if "agent" in files_lower or "orchestrat" in files_lower:
        detected.append("multiagent")
    if "dockerfile" in files_lower or "docker-compose" in files_lower:
        detected.append("docker")
    if ".tf" in files_lower or "bedrock" in files_lower:
        detected.append("aws")
    if ".github/workflows" in files_lower:
        detected.append("cicd")

    set_cache(root, cache_key, detected)
    return detected


def run_all_relevant_checks(root: Path) -> Dict[str, List[Dict]]:
    """Detect stacks and run checks in parallel."""
    stacks = detect_relevant_stacks(root)
    results = {}

    # Run checks in parallel
    with ThreadPoolExecutor(max_workers=len(stacks) or 1) as executor:
        futures = {executor.submit(run_stack_checks, sid, root): sid for sid in stacks}
        for future in futures:
            sid = futures[future]
            try:
                results[sid] = future.result()
            except Exception as e:
                results[sid] = [{"check": sid, "status": "fail", "detail": str(e)}]

    return results
