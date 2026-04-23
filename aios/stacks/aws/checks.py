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

    # v3.5.0 · AMX-CDK-WRAPPER-MISSING · regla CS03 amazon-q-rules
    # Si hay cdk.json, debe existir el wrapper cdk-admin.py / cdk-wrapper.py
    # (AMX obliga usar el wrapper, NO invocar `cdk` directo).
    cdk_json = root / "cdk.json"
    if cdk_json.exists():
        wrapper_names = ("cdk-admin.py", "cdk-wrapper.py",
                         "cdk_admin.py", "cdk_wrapper.py")
        wrapper_found = any(
            (root / name).exists() or (root / "bin" / name).exists()
            or (root / "scripts" / name).exists() or (root / "CDK" / name).exists()
            for name in wrapper_names
        )
        results.append({
            "check": "AMX-CDK-WRAPPER-MISSING (CS03)",
            "status": "pass" if wrapper_found else "fail",
            "detail": (
                "[OK] Wrapper cdk-admin.py / cdk-wrapper.py presente"
                if wrapper_found else
                "[XX] cdk.json existe pero falta cdk-admin.py / "
                "cdk-wrapper.py · amazon-q-rules CS03 prohíbe invocar "
                "'cdk' directo · agregar wrapper que exija --env {de|q|pd}"
            ),
        })

    return results
