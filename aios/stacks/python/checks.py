"""Python stack checks — optimized."""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List
from aios.core.file_scanner import scan_tracked_files, scan_source_files

def run_checks(root: Path) -> List[Dict]:
    results = []
    all_files = scan_tracked_files(root)
    py_files = scan_source_files(root, [".py"])[:80]  # SAMPLE

    has_deps = any("requirements.txt" in f or "pyproject.toml" in f for f in all_files)
    results.append({"check": "Dependency file", "status": "pass" if has_deps else "fail"})

    test_files = [f for f in all_files if "test_" in f or "_test.py" in f]
    results.append({"check": f"Tests ({len(test_files)})", "status": "pass" if test_files else "warn"})

    has_env = any(".env.example" in f for f in all_files)
    results.append({"check": ".env.example", "status": "pass" if has_env else "warn"})

    typed = untyped = 0
    for f in py_files[:40]:  # SAMPLE 40
        try:
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.strip().startswith(("def ", "async def ")):
                    if "->" in line: typed += 1
                    else: untyped += 1
        except: pass
    total = typed + untyped
    pct = round(typed / total * 100) if total > 0 else 0
    results.append({"check": f"Type hints ({pct}%)", "status": "pass" if pct > 50 else "warn"})

    has_health = False
    for f in py_files[:20]:
        try:
            if "health" in f.read_text(encoding="utf-8", errors="ignore").lower():
                has_health = True; break
        except: pass
    results.append({"check": "Health endpoint", "status": "pass" if has_health else "warn"})
    return results
