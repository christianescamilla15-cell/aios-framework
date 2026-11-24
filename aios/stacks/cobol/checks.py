"""COBOL stack checks — IBM i ILE COBOL · AS/400."""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List
from aios.core.file_scanner import scan_tracked_files


def run_checks(root: Path) -> List[Dict]:
    results = []
    all_files = scan_tracked_files(root)
    cobol_files = [f for f in all_files if f.lower().endswith((".cbl", ".cob", ".cobol", ".cpy"))]

    # Source files present
    results.append({
        "check": f"COBOL source files ({len(cobol_files)})",
        "status": "pass" if cobol_files else "warn"
    })

    # Tests detection · COBOL testing is rare
    test_files = [f for f in cobol_files if "test" in f.lower() or "spec" in f.lower()]
    results.append({
        "check": f"COBOL tests ({len(test_files)})",
        "status": "pass" if test_files else "warn"
    })

    # Hardcoded values detection (PIC X VALUE patterns)
    hardcoded_count = 0
    for f in cobol_files[:30]:
        try:
            txt = (root / f).read_text(encoding="utf-8", errors="ignore").upper()
            import re
            hardcoded_count += len(re.findall(r'PIC\s+\w+\s+VALUE\s+["\'][^"\']+["\']', txt))
        except: pass
    results.append({
        "check": f"VALUE clauses literal ({hardcoded_count})",
        "status": "warn" if hardcoded_count > 5 else "pass"
    })

    # CURSOR detection (anti-pattern in modern COBOL)
    cursor_count = 0
    for f in cobol_files[:30]:
        try:
            txt = (root / f).read_text(encoding="utf-8", errors="ignore").upper()
            if "DECLARE" in txt and "CURSOR" in txt:
                cursor_count += 1
        except: pass
    results.append({
        "check": f"CURSOR usage ({cursor_count} files)",
        "status": "warn" if cursor_count > 0 else "pass"
    })

    # File size legacy check (>1000 LOC indicates monolithic)
    big_files = []
    for f in cobol_files[:30]:
        try:
            loc = len((root / f).read_text(encoding="utf-8", errors="ignore").splitlines())
            if loc > 1000:
                big_files.append(f)
        except: pass
    results.append({
        "check": f"Monolithic files >1000 LOC ({len(big_files)})",
        "status": "warn" if big_files else "pass"
    })

    # AS/400-specific patterns
    has_as400 = False
    for f in cobol_files[:20]:
        try:
            txt = (root / f).read_text(encoding="utf-8", errors="ignore").upper()
            if any(kw in txt for kw in ["DD-", "SELECT", "ASSIGN TO DISK-", "EXEC SQL"]):
                has_as400 = True; break
        except: pass
    results.append({
        "check": "AS/400 patterns detected",
        "status": "pass" if has_as400 else "warn"
    })

    return results
