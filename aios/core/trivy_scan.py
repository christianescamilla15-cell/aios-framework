"""v3.6.5 · G-19 · Trivy container / filesystem scan wrap.

Envuelve `trivy image` o `trivy fs` para detectar CVEs en:
- Imágenes Docker (ECR · public registries · local tars)
- Filesystem (package manifests · lockfiles)

Uso:
    aios trivy-scan --image <image-tag>
    aios trivy-scan --source <path>
    aios trivy-scan --image nginx:1.21 --fail-on high
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from aios.core.external_scanner_base import (
    SEVERITY_ORDER, run_cli_capture, meets_threshold,
)


# Trivy severity · ya viene UPPERCASE: CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
_TRIVY_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "UNKNOWN": "LOW",
}


@dataclass(frozen=True)
class TrivyVulnerability:
    vuln_id: str  # CVE-2024-xxxx o GHSA-xxx
    severity: str
    package: str
    installed_version: str
    fixed_version: str
    pkg_path: str = ""
    title: str = ""


@dataclass(frozen=True)
class TrivyReport:
    target: str  # image name o filesystem path
    vulnerabilities: list[TrivyVulnerability]
    scanner_available: bool
    scan_type: str = "image"  # image | fs
    error: Optional[str] = None
    passed: bool = False
    fail_on_severity: Optional[str] = None
    violations: list[str] = field(default_factory=list)


def run_trivy(target: str, scan_type: str = "image",
              timeout_seconds: int = 600) -> dict:
    """Ejecuta `trivy <scan_type> --format json <target>`.

    scan_type: "image" (default · scan Docker/OCI image) o "fs"
    (filesystem · lockfiles · manifests).
    """
    if scan_type not in ("image", "fs"):
        return {"error": f"scan_type inválido: {scan_type} · usar image|fs"}

    cmd = ["trivy", scan_type, "--format", "json", "--quiet",
           "--severity", "CRITICAL,HIGH,MEDIUM,LOW", target]
    cli = run_cli_capture(cmd, timeout_seconds=timeout_seconds)

    if not cli.available:
        return {"scanner_available": False, "error": cli.error}

    if cli.error and not cli.stdout:
        return {"scanner_available": True, "error": cli.error}

    try:
        return json.loads(cli.stdout) if cli.stdout else {}
    except json.JSONDecodeError as e:
        return {"scanner_available": True,
                "error": f"trivy output no es JSON válido: {e}"}


def parse_trivy_output(data: dict, target: str,
                       scan_type: str = "image") -> TrivyReport:
    """Convierte output trivy JSON a TrivyReport.

    Formato Trivy:
        {
          "Results": [
            {
              "Target": "alpine:3.15 (alpine 3.15.0)",
              "Vulnerabilities": [
                {
                  "VulnerabilityID": "CVE-...",
                  "Severity": "HIGH",
                  "PkgName": "openssl",
                  "InstalledVersion": "1.1.1k",
                  "FixedVersion": "1.1.1l",
                  "Title": "...",
                }
              ]
            }
          ]
        }
    """
    if not data.get("scanner_available", True):
        return TrivyReport(target=target, vulnerabilities=[],
                           scanner_available=False, scan_type=scan_type,
                           error=data.get("error"))
    if "error" in data:
        return TrivyReport(target=target, vulnerabilities=[],
                           scanner_available=True, scan_type=scan_type,
                           error=data["error"])

    vulns: list[TrivyVulnerability] = []
    for result in data.get("Results", []):
        if not isinstance(result, dict):
            continue
        pkg_path = str(result.get("Target", ""))
        for v in result.get("Vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            severity_raw = str(v.get("Severity", "UNKNOWN")).upper()
            severity = _TRIVY_SEVERITY_MAP.get(severity_raw, "LOW")
            vulns.append(TrivyVulnerability(
                vuln_id=str(v.get("VulnerabilityID", "unknown")),
                severity=severity,
                package=str(v.get("PkgName", "")),
                installed_version=str(v.get("InstalledVersion", "")),
                fixed_version=str(v.get("FixedVersion", "") or "no fix yet"),
                pkg_path=pkg_path,
                title=str(v.get("Title", ""))[:150],
            ))

    return TrivyReport(
        target=target, vulnerabilities=vulns,
        scanner_available=True, scan_type=scan_type,
    )


def apply_gate(report: TrivyReport,
               fail_on_severity: Optional[str]) -> TrivyReport:
    if report.error or not report.scanner_available:
        return TrivyReport(
            target=report.target, vulnerabilities=report.vulnerabilities,
            scanner_available=report.scanner_available,
            scan_type=report.scan_type, error=report.error,
            passed=True, fail_on_severity=fail_on_severity, violations=[],
        )

    violations: list[str] = []
    for v in report.vulnerabilities:
        if meets_threshold(v.severity, fail_on_severity):
            violations.append(
                f"{v.severity} · {v.vuln_id} · {v.package} "
                f"{v.installed_version} (fix: {v.fixed_version})"
            )

    return TrivyReport(
        target=report.target, vulnerabilities=report.vulnerabilities,
        scanner_available=True, scan_type=report.scan_type,
        error=None, passed=len(violations) == 0,
        fail_on_severity=fail_on_severity, violations=violations,
    )


def format_human(report: TrivyReport) -> str:
    out: list[str] = ["", f"  Trivy {report.scan_type} · G-19 · CVE gate",
                      "  " + "-" * 68,
                      f"  Target        : {report.target}"]
    if not report.scanner_available:
        out.append(f"  trivy avail   : NO · {report.error}")
        out.append("  SKIPPED (no blocking)")
        out.append("")
        return "\n".join(out)
    if report.error:
        out.append(f"  ERROR · {report.error}")
        out.append("")
        return "\n".join(out)

    out.append(f"  Vulns found   : {len(report.vulnerabilities)}")
    if report.fail_on_severity:
        out.append(f"  Fail threshold: {report.fail_on_severity}")

    # Breakdown por severity
    from collections import Counter
    counts = Counter(v.severity for v in report.vulnerabilities)
    if counts:
        breakdown = " · ".join(
            f"{sev}:{counts[sev]}" for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            if counts[sev]
        )
        out.append(f"  By severity   : {breakdown}")
    out.append("")

    if report.vulnerabilities:
        out.append("  Top 20 by severity:")
        for v in sorted(
            report.vulnerabilities,
            key=lambda x: (-SEVERITY_ORDER.get(x.severity, 0), x.package)
        )[:20]:
            out.append(
                f"    · {v.severity:<8} {v.vuln_id} {v.package} "
                f"{v.installed_version} → {v.fixed_version}"
            )
        if len(report.vulnerabilities) > 20:
            out.append(f"    ... +{len(report.vulnerabilities) - 20} más")
        out.append("")

    out.append("  PASSED" if report.passed
               else f"  FAILED · {len(report.violations)} violation(s)")
    out.append("")
    return "\n".join(out)


def format_json(report: TrivyReport) -> str:
    def ser(v: TrivyVulnerability) -> dict:
        return {
            "vuln_id": v.vuln_id, "severity": v.severity,
            "package": v.package, "installed_version": v.installed_version,
            "fixed_version": v.fixed_version, "pkg_path": v.pkg_path,
            "title": v.title,
        }

    return json.dumps({
        "passed": report.passed, "target": report.target,
        "scan_type": report.scan_type,
        "scanner_available": report.scanner_available,
        "error": report.error,
        "fail_on_severity": report.fail_on_severity,
        "vulnerabilities": [ser(v) for v in report.vulnerabilities],
        "violations": report.violations,
    }, indent=2)
