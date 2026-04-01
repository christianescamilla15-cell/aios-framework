"""Smart Test Runner — detects which tests to run based on changed files."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, List

from .incremental import get_changed_files
from .file_scanner import scan_tracked_files


def find_affected_tests(root: Path) -> Dict:
    """Find tests affected by recent changes."""
    changed = get_changed_files(root, "HEAD~1")
    all_files = scan_tracked_files(root)

    # Find test files
    test_files = [f for f in all_files if "test" in f.lower() and (f.endswith(".py") or f.endswith(".js") or f.endswith(".jsx") or f.endswith(".ts"))]

    # Map changed files to their test files
    affected = []
    for cf in changed:
        cf_base = Path(cf).stem.replace(".py", "").replace(".js", "").replace(".jsx", "").replace(".ts", "")
        for tf in test_files:
            if cf_base in tf or cf_base.replace("_", "") in tf.replace("_", ""):
                affected.append(tf)

    # Also include test files that were directly changed
    for cf in changed:
        if cf in test_files:
            affected.append(cf)

    affected = sorted(set(affected))

    # Detect test framework
    framework = "unknown"
    if any(f.endswith(".py") for f in test_files):
        framework = "pytest"
    elif any("vitest" in f or ".test.js" in f or ".test.tsx" in f for f in test_files):
        framework = "vitest"
    elif any("jest" in f for f in all_files):
        framework = "jest"

    # Build run command
    if framework == "pytest":
        cmd = f"python -m pytest {' '.join(affected)} --tb=short -q" if affected else "python -m pytest --tb=short -q"
    elif framework in ("vitest", "jest"):
        cmd = f"npx vitest run {' '.join(affected)}" if affected else "npx vitest run"
    else:
        cmd = "echo 'No test framework detected'"

    return {
        "changed_files": len(changed),
        "total_tests": len(test_files),
        "affected_tests": affected,
        "framework": framework,
        "command": cmd,
    }


def run_tests(root: Path, only_affected: bool = True) -> Dict:
    """Run tests and return results."""
    info = find_affected_tests(root)

    try:
        result = subprocess.run(
            info["command"].split(), cwd=str(root),
            capture_output=True, text=True, timeout=120
        )
        return {
            **info,
            "exit_code": result.returncode,
            "passed": result.returncode == 0,
            "stdout": result.stdout[-500:] if result.stdout else "",
            "stderr": result.stderr[-500:] if result.stderr else "",
        }
    except subprocess.TimeoutExpired:
        return {**info, "exit_code": -1, "passed": False, "error": "Timeout (120s)"}
    except Exception as e:
        return {**info, "exit_code": -1, "passed": False, "error": str(e)}
