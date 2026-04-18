"""Smart Test Runner — detects which tests to run based on changed files.

v1.6.0 changes:
- Detects xUnit (.NET), NUnit (.NET), JUnit (Java), PHPUnit (PHP)
- Maps test files per stack
- Builds appropriate test command per framework
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, List

from .incremental import get_changed_files
from .file_scanner import scan_tracked_files


# Map stack → (test file pattern, framework name, run command template)
TEST_FRAMEWORKS = {
    "pytest":   {"ext": [".py"],   "patterns": ["test_", "_test.py"],         "cmd": "python -m pytest {files} --tb=short -q"},
    "vitest":   {"ext": [".js", ".jsx", ".ts", ".tsx"], "patterns": [".test.", "vitest"], "cmd": "npx vitest run {files}"},
    "jest":     {"ext": [".js", ".jsx", ".ts", ".tsx"], "patterns": ["jest", ".spec."],   "cmd": "npx jest {files}"},
    "xunit":    {"ext": [".cs"],   "patterns": ["Tests.cs", "Test.cs"],       "cmd": "dotnet test {files}"},
    "nunit":    {"ext": [".cs"],   "patterns": ["Tests.cs"],                  "cmd": "dotnet test {files}"},
    "junit":    {"ext": [".java"], "patterns": ["Test.java", "/test/"],       "cmd": "mvn test -Dtest={files}"},
    "phpunit":  {"ext": [".php"],  "patterns": ["Test.php", "/tests/"],       "cmd": "vendor/bin/phpunit {files}"},
    "gotest":   {"ext": [".go"],   "patterns": ["_test.go"],                  "cmd": "go test {files}"},
}


def detect_test_framework(root: Path, all_files: List[str]) -> str:
    """v1.6.0 · detect framework based on files present + project markers."""
    files_lower = " ".join(f.lower() for f in all_files)

    # Check project markers first (more reliable)
    if any(f.endswith(".csproj") or f.endswith(".vbproj") for f in all_files):
        # .NET project · prefer xUnit (most common modern)
        # check if NUnit or xUnit explicitly via reference
        for f in all_files[:50]:
            if f.endswith(".csproj"):
                try:
                    txt = (root / f).read_text(encoding="utf-8", errors="ignore")
                    if "nunit" in txt.lower(): return "nunit"
                    if "xunit" in txt.lower(): return "xunit"
                except: pass
        return "xunit"  # default .NET

    if "pom.xml" in files_lower or "build.gradle" in files_lower:
        return "junit"

    if "composer.json" in files_lower:
        return "phpunit"

    if "go.mod" in files_lower or any(f.endswith("_test.go") for f in all_files):
        return "gotest"

    if "package.json" in files_lower:
        # Vitest vs Jest
        for f in all_files:
            if "package.json" in f:
                try:
                    txt = (root / f).read_text(encoding="utf-8", errors="ignore").lower()
                    if "vitest" in txt: return "vitest"
                    if "jest" in txt: return "jest"
                except: pass
        return "jest"  # default JS

    if any(f.endswith(".py") for f in all_files):
        return "pytest"

    return "unknown"


def find_test_files(all_files: List[str], framework: str) -> List[str]:
    """v1.6.0 · framework-aware test file detection."""
    fw = TEST_FRAMEWORKS.get(framework)
    if not fw:
        # Fallback: any file with "test" or "spec" in name
        return [f for f in all_files if ("test" in f.lower() or "spec" in f.lower())
                and any(f.endswith(e) for e in [".py", ".js", ".ts", ".cs", ".java", ".php", ".go"])]

    test_files = []
    for f in all_files:
        if not any(f.endswith(e) for e in fw["ext"]):
            continue
        f_lower = f.lower()
        if any(pat.lower() in f_lower for pat in fw["patterns"]):
            test_files.append(f)
    return test_files


def find_affected_tests(root: Path) -> Dict:
    """Find tests affected by recent changes. v1.6.0 · multi-framework aware."""
    changed = get_changed_files(root, "HEAD~1")
    all_files = scan_tracked_files(root)

    framework = detect_test_framework(root, all_files)
    test_files = find_test_files(all_files, framework)

    # Map changed files to their test files (heuristic: stem matches)
    affected = []
    for cf in changed:
        cf_stem = Path(cf).stem
        for tf in test_files:
            tf_stem = Path(tf).stem
            # Match: ProductService.cs → ProductServiceTests.cs · ProductService_test.py · etc.
            if cf_stem in tf_stem or cf_stem.replace("_", "") in tf_stem.replace("_", ""):
                affected.append(tf)

    # Also include test files that were directly changed
    for cf in changed:
        if cf in test_files:
            affected.append(cf)

    affected = sorted(set(affected))

    # Build run command
    fw_info = TEST_FRAMEWORKS.get(framework)
    if fw_info:
        files_arg = " ".join(affected) if affected else ""
        cmd = fw_info["cmd"].format(files=files_arg).strip()
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
