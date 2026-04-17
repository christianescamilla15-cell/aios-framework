"""(.NET) stack checks — C#, VB.NET, ASP.NET legacy + .NET 8 LTS."""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List
from aios.core.file_scanner import scan_tracked_files, scan_source_files


def run_checks(root: Path) -> List[Dict]:
    results = []
    all_files = scan_tracked_files(root)
    cs_files = scan_source_files(root, [".cs", ".vb"])[:80]
    config_files = [f for f in all_files if f.endswith(".config")][:20]
    csproj_files = [f for f in all_files if f.endswith(".csproj") or f.endswith(".vbproj")]

    # Project file present
    results.append({
        "check": "Project file (.csproj/.vbproj)",
        "status": "pass" if csproj_files else "warn"
    })

    # Tests detection (xUnit / NUnit / MSTest)
    test_files = [f for f in all_files if "test" in Path(f).stem.lower() or "spec" in Path(f).stem.lower()]
    results.append({
        "check": f"Tests ({len(test_files)})",
        "status": "pass" if test_files else "warn"
    })

    # Target framework detection
    target_versions = set()
    eol_detected = False
    for fpath in csproj_files:
        try:
            txt = (root / fpath).read_text(encoding="utf-8", errors="ignore")
            for marker in ["TargetFramework", "TargetFrameworkVersion"]:
                if marker in txt:
                    # Look for version
                    import re
                    matches = re.findall(rf'{marker}>\s*v?(\d+\.\d+(?:\.\d+)?)\s*</', txt)
                    target_versions.update(matches)
        except: pass
    eol_versions = {"4.6.1", "4.7.2", "4.8"}
    for tv in target_versions:
        if tv in eol_versions or tv.startswith("4."):
            eol_detected = True
    if eol_detected:
        results.append({"check": f".NET Framework EOL detected ({sorted(target_versions)})", "status": "fail"})
    elif target_versions:
        results.append({"check": f".NET version ({sorted(target_versions)})", "status": "pass"})
    else:
        results.append({"check": ".NET version", "status": "warn"})

    # customErrors mode=Off detection
    custom_errors_off = False
    for cfg in config_files:
        try:
            txt = (root / cfg).read_text(encoding="utf-8", errors="ignore")
            if 'customErrors' in txt and 'Off' in txt:
                custom_errors_off = True
                break
        except: pass
    results.append({
        "check": "customErrors mode=Off (CWE-209)",
        "status": "fail" if custom_errors_off else "pass"
    })

    # debug=true detection
    debug_true = False
    for cfg in config_files:
        try:
            txt = (root / cfg).read_text(encoding="utf-8", errors="ignore")
            if 'debug="true"' in txt or "debug='true'" in txt:
                debug_true = True
                break
        except: pass
    results.append({
        "check": "compilation debug=true",
        "status": "fail" if debug_true else "pass"
    })

    # Hardcoded credentials check (config files)
    cred_count = 0
    for cfg in config_files:
        try:
            txt = (root / cfg).read_text(encoding="utf-8", errors="ignore")
            import re
            cred_count += len(re.findall(r'(?i)(password|pwd)\s*=\s*["\'][^"\']+["\']', txt))
        except: pass
    results.append({
        "check": f"Hardcoded credentials ({cred_count})",
        "status": "fail" if cred_count > 0 else "pass"
    })

    # Health endpoint detection
    has_health = False
    for f in cs_files[:20]:
        try:
            if "health" in f.read_text(encoding="utf-8", errors="ignore").lower():
                has_health = True; break
        except: pass
    results.append({
        "check": "Health endpoint",
        "status": "pass" if has_health else "warn"
    })

    # SABRE/external retry policy detection
    has_polly = any("Polly" in (root / f).read_text(encoding="utf-8", errors="ignore")
                    for f in [str(c) for c in csproj_files] if (root / f).exists())
    results.append({
        "check": "Resilience library (Polly)",
        "status": "pass" if has_polly else "warn"
    })

    return results
