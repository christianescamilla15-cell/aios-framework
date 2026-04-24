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
    """Busca coverage xml recursivamente bajo `root` (single file · legacy API).

    Prioridad: `TestResults/*/coverage.cobertura.xml` (coverlet default).
    Fallback: cualquier `*.cobertura.xml` · `cobertura.xml` · `coverage.xml`.
    """
    files = find_cobertura_files(root)
    return files[-1] if files else None


def find_cobertura_files(root: Path) -> list[Path]:
    """v3.6.2 · retorna TODOS los cobertura.xml bajo `root` · para soluciones
    multi-proyecto (N test projects · N coverage files). Se usa con
    `parse_cobertura_merged` para consolidar el reporte.

    No deduplica · si hay overlap de packages entre archivos,
    `parse_cobertura_merged` resuelve tomando el de mayor lines_valid.
    """
    found: list[Path] = []
    seen: set[Path] = set()
    for pattern in ("coverage.cobertura.xml", "*.cobertura.xml",
                    "cobertura.xml", "coverage.xml"):
        for match in root.rglob(pattern):
            resolved = match.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            found.append(match)
    return sorted(found, key=lambda p: str(p))


def _pkg_counters_from_classes(pkg_elem) -> tuple[int, int, int, int]:
    """Suma lines/branches valid+covered a partir de los elementos `<class>`
    hijos del `<package>`. Coverlet NO pone `lines-valid` a nivel package,
    solo a nivel class y root · este helper lo calcula bottom-up.
    """
    lines_valid = 0
    lines_covered = 0
    branches_valid = 0
    branches_covered = 0
    for cls in pkg_elem.iter("class"):
        # Contar cada <line> dentro de <methods>/<class> una sola vez.
        # coverlet genera <lines> bajo <class> con <line number="N" hits="X"
        # branch="true/false" condition-coverage="X/Y"/>
        for line_elem in cls.iter("line"):
            lines_valid += 1
            if int(line_elem.get("hits", "0") or "0") > 0:
                lines_covered += 1
            # Branches: si la línea tiene condition-coverage, parsea M/N
            cc = line_elem.get("condition-coverage", "")
            if cc and "(" in cc:
                try:
                    # format: "50% (1/2)"
                    inner = cc[cc.index("(") + 1 : cc.rindex(")")]
                    cov_str, val_str = inner.split("/")
                    branches_covered += int(cov_str.strip())
                    branches_valid += int(val_str.strip())
                except (ValueError, IndexError):
                    pass
    return lines_valid, lines_covered, branches_valid, branches_covered


def parse_cobertura_merged(xml_paths: list[Path],
                           sox_pattern: Optional[str] = None) -> CoverageReport:
    """v3.6.2 · parsea N archivos cobertura.xml y consolida en un reporte
    único. Cada package se representa una sola vez · si aparece en
    múltiples archivos · se toma el de mayor `lines_covered` (más tests
    ejercieron ese package). Totales globales se recalculan sumando
    lines_valid · lines_covered · branches_valid · branches_covered de
    los packages seleccionados como canonicales.
    """
    if not xml_paths:
        raise ValueError("parse_cobertura_merged requires at least 1 path")

    sox_re = re.compile(sox_pattern) if sox_pattern else None
    packages_by_name: dict[str, PackageCoverage] = {}
    source_files: list[str] = []

    for xml_path in xml_paths:
        source_files.append(str(xml_path))
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for pkg in root.iter("package"):
            name = pkg.get("name", "")
            lr = float(pkg.get("line-rate", "0") or "0")
            br = float(pkg.get("branch-rate", "0") or "0")
            lv, lc, bv, bc = _pkg_counters_from_classes(pkg)
            candidate = PackageCoverage(
                name=name,
                line_rate=lr,
                branch_rate=br,
                lines_covered=lc,
                lines_valid=lv,
                branches_covered=bc,
                branches_valid=bv,
                is_sox_critical=bool(sox_re and sox_re.search(name)),
            )
            existing = packages_by_name.get(name)
            # Preferir el package con MÁS lines_covered (el test project
            # que más ejercitó este package · representa el best observed
            # coverage para él).
            if (existing is None or candidate.lines_covered > existing.lines_covered
                    or (candidate.lines_covered == existing.lines_covered
                        and candidate.branches_covered > existing.branches_covered)):
                packages_by_name[name] = candidate

    packages = list(packages_by_name.values())
    total_lv = sum(p.lines_valid for p in packages)
    total_lc = sum(p.lines_covered for p in packages)
    total_bv = sum(p.branches_valid for p in packages)
    total_bc = sum(p.branches_covered for p in packages)
    global_lr = (total_lc / total_lv) if total_lv > 0 else 0.0
    global_br = (total_bc / total_bv) if total_bv > 0 else 0.0

    return CoverageReport(
        line_rate=global_lr,
        branch_rate=global_br,
        lines_covered=total_lc,
        lines_valid=total_lv,
        branches_covered=total_bc,
        branches_valid=total_bv,
        packages=packages,
        source_file=" + ".join(source_files) if len(source_files) > 1
                    else (source_files[0] if source_files else ""),
        passed=False,
        violations=[],
    )


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
