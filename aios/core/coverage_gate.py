"""v3.6.0 · G-06 · Coverage Gate · T0 SOX enforcement.

Parsea cobertura.xml (formato coverlet · Jacoco-compatible) y compara
contra umbrales configurables. Exit 1 si falla · exit 0 si pasa.

Uso:
    aios coverage --root <path> --min-line 80 --sox-threshold 100
    aios coverage --cobertura-file TestResults/xxx/coverage.cobertura.xml

Diseñado para pipelines AMX T0:
- coverage ≥ 80 % lines · 80 % branches (baseline T0)
- coverage = 100 % en paquetes SOX-critical (via --sox-pattern regex)
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class PackageCoverage:
    """Coverage metrics for a single package."""
    name: str
    line_rate: float
    branch_rate: float
    lines_covered: int
    lines_valid: int
    branches_covered: int
    branches_valid: int
    is_sox_critical: bool = False


@dataclass(frozen=True)
class CoverageReport:
    """Complete coverage report with gate decision."""
    line_rate: float
    branch_rate: float
    lines_covered: int
    lines_valid: int
    branches_covered: int
    branches_valid: int
    packages: list[PackageCoverage]
    source_file: str
    passed: bool
    violations: list[str]


def find_cobertura_file(root: Path) -> Optional[Path]:
    """Busca coverage xml recursivamente bajo `root`.

    Prioridad: `TestResults/*/coverage.cobertura.xml` (coverlet default).
    Fallback: cualquier `*.cobertura.xml` · `cobertura.xml` · `coverage.xml`.
    """
    for pattern in ("coverage.cobertura.xml", "*.cobertura.xml",
                    "cobertura.xml", "coverage.xml"):
        matches = sorted(root.rglob(pattern))
        if matches:
            return matches[-1]
    return None


def parse_cobertura(xml_path: Path,
                    sox_pattern: Optional[str] = None) -> CoverageReport:
    """Parsea `cobertura.xml` (formato coverlet)."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    sox_re = re.compile(sox_pattern) if sox_pattern else None

    def fattr(a: str) -> float:
        try:
            return float(root.get(a, "0") or "0")
        except (TypeError, ValueError):
            return 0.0

    def iattr(a: str) -> int:
        try:
            return int(root.get(a, "0") or "0")
        except (TypeError, ValueError):
            return 0

    packages: list[PackageCoverage] = []
    for pkg in root.iter("package"):
        name = pkg.get("name", "")
        lv = int(pkg.get("lines-valid", "0") or "0")
        lr = float(pkg.get("line-rate", "0") or "0")
        bv = int(pkg.get("branches-valid", "0") or "0")
        br = float(pkg.get("branch-rate", "0") or "0")
        packages.append(PackageCoverage(
            name=name,
            line_rate=lr,
            branch_rate=br,
            lines_covered=round(lr * lv),
            lines_valid=lv,
            branches_covered=round(br * bv),
            branches_valid=bv,
            is_sox_critical=bool(sox_re and sox_re.search(name)),
        ))

    return CoverageReport(
        line_rate=fattr("line-rate"),
        branch_rate=fattr("branch-rate"),
        lines_covered=iattr("lines-covered"),
        lines_valid=iattr("lines-valid"),
        branches_covered=iattr("branches-covered"),
        branches_valid=iattr("branches-valid"),
        packages=packages,
        source_file=str(xml_path),
        passed=False,
        violations=[],
    )


def apply_gate(report: CoverageReport, min_line: float, min_branch: float,
               sox_threshold: float) -> CoverageReport:
    """Aplica umbrales al report · retorna nuevo report con `passed` + violations."""
    violations: list[str] = []

    line_pct = report.line_rate * 100
    branch_pct = report.branch_rate * 100

    if line_pct < min_line:
        violations.append(
            f"Global line coverage {line_pct:.1f}% < threshold {min_line:.1f}%"
        )
    if branch_pct < min_branch:
        violations.append(
            f"Global branch coverage {branch_pct:.1f}% < threshold {min_branch:.1f}%"
        )

    for pkg in report.packages:
        if not pkg.is_sox_critical:
            continue
        pl = pkg.line_rate * 100
        pb = pkg.branch_rate * 100
        if pl < sox_threshold:
            violations.append(
                f"SOX-critical {pkg.name} line {pl:.1f}% < "
                f"SOX threshold {sox_threshold:.1f}%"
            )
        if pb < sox_threshold:
            violations.append(
                f"SOX-critical {pkg.name} branch {pb:.1f}% < "
                f"SOX threshold {sox_threshold:.1f}%"
            )

    return CoverageReport(
        line_rate=report.line_rate,
        branch_rate=report.branch_rate,
        lines_covered=report.lines_covered,
        lines_valid=report.lines_valid,
        branches_covered=report.branches_covered,
        branches_valid=report.branches_valid,
        packages=report.packages,
        source_file=report.source_file,
        passed=len(violations) == 0,
        violations=violations,
    )


def format_human(report: CoverageReport, min_line: float, min_branch: float,
                 sox_threshold: float) -> str:
    """Formatea el report para terminal."""
    out: list[str] = []
    out.append("")
    out.append("  Coverage Gate · G-06 · T0 SOX enforcement")
    out.append("  " + "-" * 68)
    out.append(f"  Source file   : {report.source_file}")
    out.append(
        f"  Thresholds    : line >= {min_line:.1f}% · "
        f"branch >= {min_branch:.1f}% · SOX >= {sox_threshold:.1f}%"
    )
    out.append("")
    out.append(
        f"  GLOBAL · lines {report.line_rate*100:.1f}% "
        f"({report.lines_covered}/{report.lines_valid}) · "
        f"branches {report.branch_rate*100:.1f}% "
        f"({report.branches_covered}/{report.branches_valid})"
    )
    out.append("")

    if report.packages:
        out.append("  By package:")
        for pkg in sorted(report.packages, key=lambda p: p.name):
            sox_tag = " [SOX]" if pkg.is_sox_critical else ""
            out.append(
                f"    · {pkg.name}{sox_tag} · lines {pkg.line_rate*100:.1f}% · "
                f"branches {pkg.branch_rate*100:.1f}%"
            )
        out.append("")

    if report.passed:
        out.append("  PASSED · coverage meets all thresholds")
    else:
        out.append(f"  FAILED · {len(report.violations)} violation(s):")
        for v in report.violations:
            out.append(f"    - {v}")
    out.append("")
    return "\n".join(out)


def format_json(report: CoverageReport) -> str:
    """Serializa el report a JSON."""
    def ser(p: PackageCoverage) -> dict:
        return {
            "name": p.name,
            "line_rate": p.line_rate,
            "branch_rate": p.branch_rate,
            "lines_covered": p.lines_covered,
            "lines_valid": p.lines_valid,
            "branches_covered": p.branches_covered,
            "branches_valid": p.branches_valid,
            "is_sox_critical": p.is_sox_critical,
        }

    return json.dumps({
        "passed": report.passed,
        "source_file": report.source_file,
        "line_rate": report.line_rate,
        "branch_rate": report.branch_rate,
        "lines_covered": report.lines_covered,
        "lines_valid": report.lines_valid,
        "branches_covered": report.branches_covered,
        "branches_valid": report.branches_valid,
        "packages": [ser(p) for p in report.packages],
        "violations": report.violations,
    }, indent=2)
