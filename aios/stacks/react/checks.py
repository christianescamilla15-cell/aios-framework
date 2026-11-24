"""React stack checks."""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List
from aios.core.file_scanner import scan_tracked_files, scan_source_files


def run_checks(root: Path) -> List[Dict]:
    results = []
    all_files = scan_tracked_files(root)
    js_files = scan_source_files(root, [".js", ".jsx", ".ts", ".tsx"])

    results.append({"check": "package.json", "status": "pass" if any("package.json" in f for f in all_files) else "fail"})
    results.append({"check": "Vite config", "status": "pass" if any("vite.config" in f for f in all_files) else "warn"})

    tests = [f for f in all_files if ".test." in f or ".spec." in f]
    results.append({"check": f"Tests ({len(tests)})", "status": "pass" if tests else "warn"})

    # No hardcoded keys in source
    suspicious = []
    for f in js_files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            if any(k in content for k in ["sk-ant-", "gsk_", "AKIA"]):
                if "import.meta.env" not in content and "process.env" not in content:
                    suspicious.append(str(f.relative_to(root)))
        except Exception: pass
    results.append({"check": "No hardcoded keys", "status": "fail" if suspicious else "pass",
                     "detail": f"Found: {suspicious[:3]}" if suspicious else "Clean"})

    results.append({"check": "Build output (dist/)", "status": "pass" if (root / "dist").exists() else "info"})

    return results
