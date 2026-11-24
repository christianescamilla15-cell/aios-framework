"""PHP stack checks — PHP 8.x · Composer · Laravel/Symfony / plain PHP legacy."""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List
from aios.core.file_scanner import scan_tracked_files


def run_checks(root: Path) -> List[Dict]:
    results = []
    all_files = scan_tracked_files(root)
    php_files = [f for f in all_files if f.endswith(".php")]

    # Composer detection
    has_composer = any("composer.json" in f for f in all_files)
    results.append({
        "check": "Composer (composer.json)",
        "status": "pass" if has_composer else "warn"
    })

    # Tests detection (PHPUnit)
    test_files = [f for f in php_files if "Test.php" in f or "/tests/" in f or "/test/" in f]
    results.append({
        "check": f"Tests ({len(test_files)})",
        "status": "pass" if test_files else "warn"
    })

    # Framework detection (Laravel/Symfony)
    framework = None
    for f in all_files:
        if "artisan" in f: framework = "Laravel"; break
        if "symfony.lock" in f: framework = "Symfony"; break
    results.append({
        "check": f"Framework: {framework if framework else 'plain PHP'}",
        "status": "pass" if framework else "warn"
    })

    # Hardcoded credentials
    cred_count = 0
    for f in php_files[:30]:
        try:
            txt = (root / f).read_text(encoding="utf-8", errors="ignore")
            import re
            cred_count += len(re.findall(r'(?i)\$(password|pwd|secret|api_?key)\s*=\s*["\'][^"\']+["\'];', txt))
        except: pass
    results.append({
        "check": f"Hardcoded credentials ({cred_count})",
        "status": "fail" if cred_count > 0 else "pass"
    })

    # SQL injection patterns (concat in mysqli_query/PDO)
    sqli_risk = 0
    for f in php_files[:30]:
        try:
            txt = (root / f).read_text(encoding="utf-8", errors="ignore")
            import re
            sqli_risk += len(re.findall(r'(mysqli_query|->query)\s*\([^)]*\$_(GET|POST|REQUEST)', txt))
        except: pass
    results.append({
        "check": f"Potential SQL injection ({sqli_risk})",
        "status": "fail" if sqli_risk > 0 else "pass"
    })

    # XSS risk (echo $_GET/POST without sanitizer)
    xss_risk = 0
    for f in php_files[:30]:
        try:
            txt = (root / f).read_text(encoding="utf-8", errors="ignore")
            import re
            xss_risk += len(re.findall(r'echo\s+\$_(GET|POST|REQUEST)\[', txt))
        except: pass
    results.append({
        "check": f"Potential XSS ({xss_risk})",
        "status": "fail" if xss_risk > 0 else "pass"
    })

    # shell_exec / eval / system risk
    shell_risk = 0
    for f in php_files[:30]:
        try:
            txt = (root / f).read_text(encoding="utf-8", errors="ignore")
            import re
            shell_risk += len(re.findall(r'\b(shell_exec|exec|system|passthru|eval)\s*\(', txt))
        except: pass
    results.append({
        "check": f"Dangerous functions (shell_exec/eval/system) ({shell_risk})",
        "status": "warn" if shell_risk > 0 else "pass"
    })

    return results
