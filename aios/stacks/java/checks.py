"""Java stack checks — Spring Boot · JDK 17/21 · Maven/Gradle."""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List
from aios.core.file_scanner import scan_tracked_files


def run_checks(root: Path) -> List[Dict]:
    results = []
    all_files = scan_tracked_files(root)
    java_files = [f for f in all_files if f.endswith(".java")]

    # Build tool detection
    has_maven = any("pom.xml" in f for f in all_files)
    has_gradle = any("build.gradle" in f or "build.gradle.kts" in f for f in all_files)
    if has_maven:
        results.append({"check": "Maven (pom.xml)", "status": "pass"})
    elif has_gradle:
        results.append({"check": "Gradle build.gradle", "status": "pass"})
    else:
        results.append({"check": "Build tool (Maven/Gradle)", "status": "warn"})

    # Tests detection (JUnit pattern)
    test_files = [f for f in java_files if "Test.java" in f or "/test/" in f]
    results.append({
        "check": f"Tests ({len(test_files)})",
        "status": "pass" if test_files else "warn"
    })

    # Spring Boot detection
    has_spring = False
    for f in java_files[:30]:
        try:
            txt = (root / f).read_text(encoding="utf-8", errors="ignore")
            if "@SpringBootApplication" in txt or "org.springframework.boot" in txt:
                has_spring = True; break
        except: pass
    results.append({
        "check": "Spring Boot framework",
        "status": "pass" if has_spring else "warn"
    })

    # Health endpoint detection
    has_actuator = False
    for f in java_files[:30]:
        try:
            if "actuator" in (root / f).read_text(encoding="utf-8", errors="ignore").lower():
                has_actuator = True; break
        except: pass
    results.append({
        "check": "Spring Actuator (health/metrics)",
        "status": "pass" if has_actuator else "warn"
    })

    # Hardcoded credentials check
    cred_count = 0
    for f in java_files[:40]:
        try:
            txt = (root / f).read_text(encoding="utf-8", errors="ignore")
            import re
            cred_count += len(re.findall(r'(?i)(password|pwd|secret)\s*=\s*"[^"]+";', txt))
        except: pass
    results.append({
        "check": f"Hardcoded credentials ({cred_count})",
        "status": "fail" if cred_count > 0 else "pass"
    })

    # Generic catch (Exception) detection
    catch_generic = 0
    for f in java_files[:40]:
        try:
            txt = (root / f).read_text(encoding="utf-8", errors="ignore")
            import re
            catch_generic += len(re.findall(r'catch\s*\(\s*Exception\s+\w+\s*\)', txt))
        except: pass
    results.append({
        "check": f"catch (Exception) generic ({catch_generic})",
        "status": "warn" if catch_generic > 5 else "pass"
    })

    # Resilience library (Resilience4j)
    has_resilience = False
    for f in all_files:
        if "pom.xml" in f or "build.gradle" in f:
            try:
                txt = (root / f).read_text(encoding="utf-8", errors="ignore")
                if "resilience4j" in txt or "hystrix" in txt:
                    has_resilience = True; break
            except: pass
    results.append({
        "check": "Resilience library (Resilience4j)",
        "status": "pass" if has_resilience else "warn"
    })

    return results
