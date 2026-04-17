"""Module Loader — loads and runs stack-specific checks (optimized).

v1.5.0 changes:
- Added stacks: dotnet, cobol, java, php
- Multi-app detection: scans subdirectories (e.g. apps_code/*/) for per-app stacks
- Detection per app for monorepo-like structures
"""
from __future__ import annotations

import importlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List

from .cache import get_cache, set_cache
from .file_scanner import scan_tracked_files

AVAILABLE_STACKS = [
    "multiagent", "python", "cicd", "react", "aws", "docker",
    # New in v1.5.0
    "dotnet", "cobol", "java", "php",
]


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


def _detect_stacks_from_files(files: List[str]) -> List[str]:
    """Pure detection logic from a file list. Reusable per app."""
    files_lower = " ".join(f.lower() for f in files)
    detected = []

    # Python
    if "requirements.txt" in files_lower or "pyproject.toml" in files_lower or ".py " in files_lower or files_lower.endswith(".py"):
        detected.append("python")
    # React
    if "package.json" in files_lower and ("jsx" in files_lower or "tsx" in files_lower):
        detected.append("react")
    # Multiagent
    if "agent" in files_lower or "orchestrat" in files_lower:
        detected.append("multiagent")
    # Docker
    if "dockerfile" in files_lower or "docker-compose" in files_lower:
        detected.append("docker")
    # AWS
    if ".tf" in files_lower or "bedrock" in files_lower or "cloudformation" in files_lower:
        detected.append("aws")
    # CI/CD
    if ".github/workflows" in files_lower or ".gitlab-ci" in files_lower:
        detected.append("cicd")
    # NEW v1.5.0
    if ".cs" in files_lower or ".csproj" in files_lower or ".vb" in files_lower or ".vbproj" in files_lower or "web.config" in files_lower:
        detected.append("dotnet")
    if ".cbl" in files_lower or ".cob" in files_lower or ".cobol" in files_lower or ".cpy" in files_lower:
        detected.append("cobol")
    if ".java" in files_lower or "pom.xml" in files_lower or "build.gradle" in files_lower:
        detected.append("java")
    if ".php" in files_lower or "composer.json" in files_lower:
        detected.append("php")

    return list(dict.fromkeys(detected))  # preserve order, dedup


def detect_relevant_stacks(root: Path) -> List[str]:
    """Fast stack detection using git ls-files (not rglob)."""
    cache_key = "detected_stacks"
    cached = get_cache(root, cache_key)
    if cached is not None:
        return cached

    files = scan_tracked_files(root)
    detected = _detect_stacks_from_files(files)

    set_cache(root, cache_key, detected)
    return detected


def detect_stacks_per_app(root: Path, apps_dir: str = "apps_code") -> Dict[str, List[str]]:
    """v1.5.0 NEW · detect stacks per subdirectory under apps_code/.

    Useful for multi-app projects where each app folder has its own stack.
    Returns: {"01_app_name": ["dotnet", "docker"], ...}
    """
    apps_root = root / apps_dir
    if not apps_root.exists():
        return {}

    cache_key = f"stacks_per_app_{apps_dir}"
    cached = get_cache(root, cache_key)
    if cached is not None:
        return cached

    result = {}
    for app_dir in sorted(apps_root.iterdir()):
        if not app_dir.is_dir() or app_dir.name.startswith("."):
            continue
        # Walk app dir
        files = []
        for f in app_dir.rglob("*"):
            if f.is_file():
                # Skip common ignored
                if any(p in f.parts for p in ("bin", "obj", "node_modules", "__pycache__", ".vs", "packages", ".memory", ".agents", "analysis_output")):
                    continue
                files.append(str(f.relative_to(root)))
        result[app_dir.name] = _detect_stacks_from_files(files)

    set_cache(root, cache_key, result)
    return result


def run_all_relevant_checks(root: Path) -> Dict[str, List[Dict]]:
    """Detect stacks and run checks in parallel."""
    stacks = detect_relevant_stacks(root)
    results = {}

    if not stacks:
        return results

    with ThreadPoolExecutor(max_workers=len(stacks) or 1) as executor:
        futures = {executor.submit(run_stack_checks, sid, root): sid for sid in stacks}
        for future in futures:
            sid = futures[future]
            try:
                results[sid] = future.result()
            except Exception as e:
                results[sid] = [{"check": sid, "status": "fail", "detail": str(e)}]

    return results
