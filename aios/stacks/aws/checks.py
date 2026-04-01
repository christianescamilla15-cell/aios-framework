"""AWS stack checks."""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List
from aios.core.file_scanner import scan_tracked_files, scan_source_files


def run_checks(root: Path) -> List[Dict]:
    results = []
    all_files = scan_tracked_files(root)
    src_files = scan_source_files(root)

    tf_files = [f for f in all_files if f.endswith(".tf")]
    results.append({"check": f"Terraform ({len(tf_files)})", "status": "pass" if tf_files else "info"})

    has_aws = any("aws" in f.read_text(encoding="utf-8", errors="ignore").lower() for f in src_files)
    results.append({"check": "AWS references", "status": "pass" if has_aws else "info"})

    # No AWS credentials — only check source files, not node_modules
    suspicious = []
    for f in src_files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            if "AKIA" in content or "aws_secret_access_key" in content:
                suspicious.append(str(f.relative_to(root)))
        except Exception: pass
    results.append({"check": "No AWS credentials", "status": "fail" if suspicious else "pass",
                     "detail": f"Found: {suspicious[:3]}" if suspicious else "Clean"})

    return results
