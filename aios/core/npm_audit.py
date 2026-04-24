"""v3.6.4 · G-17 · npm audit supply-chain wrap.

Envuelve `npm audit --json` para integrar findings de dependencias
vulnerables al pipeline AIOS. Convierte el output npm a formato Finding
unificado para que `aios release` pueda consumirlo.

Uso:
    aios npm-audit --root frontend/
    aios npm-audit --root frontend/ --fail-on high
    aios npm-audit --root frontend/ --format json

Diseñado para policies AMX frontend (Angular / React SPA):
- CWE-1104 (EOL packages · Angular ≤16 ya cubierto por G-10)
- CWE-1395 (dependency con vulnerability known)
- CWE-937 (components with known vulnerabilities · OWASP A06:2021)
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# npm audit severity → AIOS severity map (npm usa lowercase strings)
_NPM_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "moderate": "MEDIUM",
    "low": "LOW",
    "info": "LOW",
}

# Orden para --fail-on threshold comparisons
_SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class NpmVulnerability:
    """Un paquete con una o más vulnerabilidades reportadas por npm audit."""
    package: str
    severity: str  # CRITICAL|HIGH|MEDIUM|LOW
    current_version: str
    fix_available: bool
    advisories: tuple[str, ...] = ()  # ids GHSA / CVE
    direct: bool = False  # True si es top-level (no transitive)


@dataclass(frozen=True)
class NpmAuditReport:
    """Resultado consolidado de `npm audit`."""
    root: str
    vulnerabilities: list[NpmVulnerability]
    total_packages_scanned: int
    npm_available: bool
    error: Optional[str] = None
    raw_metadata: dict = field(default_factory=dict)
    passed: bool = False
    fail_on_severity: Optional[str] = None
    violations: list[str] = field(default_factory=list)


def run_npm_audit(root: Path, production_only: bool = False,
                  timeout_seconds: int = 120) -> dict:
    """Ejecuta `npm audit --json` en `root` y retorna dict parseado.

    Si npm no está disponible, retorna dict con `"npm_available": False`.
    Si el comando falla por razón operacional (no vulns encontradas
    retorna exit 0 · con vulns retorna exit 1 · que NO es error real),
    igual parseamos el JSON output.
    """
    if shutil.which("npm") is None:
        return {"npm_available": False,
                "error": "npm CLI no encontrado en PATH"}

    if not (root / "package.json").exists():
        return {"npm_available": True,
                "error": f"{root}/package.json no existe"}

    cmd = ["npm", "audit", "--json"]
    if production_only:
        cmd.append("--omit=dev")

    try:
        result = subprocess.run(
            cmd, cwd=root, capture_output=True, text=True,
            timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"npm_available": True,
                "error": f"npm audit timeout ({timeout_seconds}s)"}
    except OSError as e:
        return {"npm_available": True, "error": f"subprocess error: {e}"}

    # npm audit exit code:
    # 0 · no vulns · 1 · vulns encontradas (esperado · no es error)
    # 2+ · error real (package.json corrupto · red abajo · etc)
    if result.returncode >= 2 and not result.stdout:
        return {"npm_available": True,
                "error": f"npm audit fallo · exit {result.returncode} · "
                         f"stderr: {result.stderr[:300]}"}

    try:
        return json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError as e:
        return {"npm_available": True,
                "error": f"npm audit output no es JSON válido: {e}"}


def parse_npm_audit_output(data: dict,
                           root: str) -> NpmAuditReport:
    """Convierte el output de `npm audit --json` a NpmAuditReport.

    Soporta el formato npm v7+ (default en Node 16+) donde el dict tiene
    estructura:
        {
          "vulnerabilities": {
            "<pkg-name>": {
              "name": "<pkg-name>",
              "severity": "high",
              "isDirect": true|false,
              "via": [...],
              "fixAvailable": true|false|{...},
              ...
            }
          },
          "metadata": {
            "vulnerabilities": {"total": N, "critical": N, "high": N, ...},
            "totalDependencies": N
          }
        }
    """
    if not data.get("npm_available", True):
        return NpmAuditReport(
            root=root, vulnerabilities=[], total_packages_scanned=0,
            npm_available=False, error=data.get("error", "npm no disponible"),
        )

    if "error" in data:
        return NpmAuditReport(
            root=root, vulnerabilities=[], total_packages_scanned=0,
            npm_available=True, error=data["error"],
        )

    vulns_raw = data.get("vulnerabilities", {})
    metadata = data.get("metadata", {})
    total_deps = metadata.get("totalDependencies", 0)

    vulns: list[NpmVulnerability] = []
    for pkg_name, info in vulns_raw.items():
        if not isinstance(info, dict):
            continue
        severity_raw = str(info.get("severity", "")).lower()
        severity = _NPM_SEVERITY_MAP.get(severity_raw, "MEDIUM")
        range_str = info.get("range", "") or ""
        current = info.get("version") or range_str or "unknown"
        fix_avail_raw = info.get("fixAvailable", False)
        # fixAvailable puede ser bool · también objeto {name, version, isSemVerMajor}
        fix_available = bool(fix_avail_raw)

        # Extraer advisories de "via" (array de ids o dicts)
        advisories: list[str] = []
        via = info.get("via", [])
        if isinstance(via, list):
            for v in via:
                if isinstance(v, dict):
                    adv_id = v.get("source") or v.get("url") or v.get("name")
                    if adv_id:
                        advisories.append(str(adv_id))
                elif isinstance(v, str):
                    advisories.append(v)

        vulns.append(NpmVulnerability(
            package=pkg_name,
            severity=severity,
            current_version=str(current),
            fix_available=fix_available,
            advisories=tuple(advisories[:5]),  # cap para output limpio
            direct=bool(info.get("isDirect", False)),
        ))

    return NpmAuditReport(
        root=root, vulnerabilities=vulns,
        total_packages_scanned=total_deps,
        npm_available=True, raw_metadata=metadata,
    )


def apply_gate(report: NpmAuditReport,
               fail_on_severity: Optional[str]) -> NpmAuditReport:
    """Aplica el gate · si hay vulns >= fail_on_severity · passed=False.

    fail_on_severity puede ser None (solo reporta · nunca falla), o uno de
    LOW|MEDIUM|HIGH|CRITICAL (bloquea si hay ≥ este nivel).
    """
    violations: list[str] = []
    threshold = _SEVERITY_ORDER.get((fail_on_severity or "").upper(), 0)

    if report.error or not report.npm_available:
        # No aplica gate · reportamos pero no bloqueamos
        return NpmAuditReport(
            root=report.root, vulnerabilities=report.vulnerabilities,
            total_packages_scanned=report.total_packages_scanned,
            npm_available=report.npm_available, error=report.error,
            raw_metadata=report.raw_metadata,
            passed=True, fail_on_severity=fail_on_severity, violations=[],
        )

    if threshold > 0:
        for v in report.vulnerabilities:
            if _SEVERITY_ORDER.get(v.severity, 0) >= threshold:
                violations.append(
                    f"{v.severity} · {v.package} {v.current_version} · "
                    f"{'DIRECT' if v.direct else 'transitive'}"
                )

    passed = len(violations) == 0

    return NpmAuditReport(
        root=report.root, vulnerabilities=report.vulnerabilities,
        total_packages_scanned=report.total_packages_scanned,
        npm_available=report.npm_available, error=report.error,
        raw_metadata=report.raw_metadata,
        passed=passed, fail_on_severity=fail_on_severity,
        violations=violations,
    )


def format_human(report: NpmAuditReport) -> str:
    """Formatea el report para terminal."""
    out: list[str] = []
    out.append("")
    out.append("  npm audit · G-17 · supply-chain gate")
    out.append("  " + "-" * 68)
    out.append(f"  Root          : {report.root}")

    if not report.npm_available:
        out.append(f"  npm available : NO · {report.error}")
        out.append("  SKIPPED (no blocking)")
        out.append("")
        return "\n".join(out)

    if report.error:
        out.append(f"  ERROR · {report.error}")
        out.append("")
        return "\n".join(out)

    out.append(f"  Total deps    : {report.total_packages_scanned}")
    out.append(f"  Vulns found   : {len(report.vulnerabilities)}")
    if report.fail_on_severity:
        out.append(f"  Fail threshold: {report.fail_on_severity}")
    out.append("")

    if report.vulnerabilities:
        out.append("  By package:")
        for v in sorted(
            report.vulnerabilities,
            key=lambda x: (-_SEVERITY_ORDER.get(x.severity, 0), x.package)
        ):
            kind = "DIRECT" if v.direct else "transitive"
            fix = " · fix available" if v.fix_available else ""
            out.append(
                f"    · {v.severity:<8} {v.package} {v.current_version} "
                f"[{kind}]{fix}"
            )
        out.append("")

    if report.passed:
        out.append("  PASSED · no vulns above threshold")
    else:
        out.append(f"  FAILED · {len(report.violations)} violation(s)")
    out.append("")
    return "\n".join(out)


def format_json(report: NpmAuditReport) -> str:
    """Serializa el report a JSON."""
    def ser(v: NpmVulnerability) -> dict:
        return {
            "package": v.package,
            "severity": v.severity,
            "current_version": v.current_version,
            "fix_available": v.fix_available,
            "advisories": list(v.advisories),
            "direct": v.direct,
        }

    return json.dumps({
        "passed": report.passed,
        "root": report.root,
        "npm_available": report.npm_available,
        "error": report.error,
        "total_packages_scanned": report.total_packages_scanned,
        "fail_on_severity": report.fail_on_severity,
        "vulnerabilities": [ser(v) for v in report.vulnerabilities],
        "violations": report.violations,
    }, indent=2)
