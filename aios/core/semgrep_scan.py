"""v3.6.5 · G-18 · Semgrep SAST wrap.

Envuelve `semgrep scan --json` para integrar findings SAST al pipeline
AIOS. Se sugiere usar `--config p/ci` o `--config auto` · ambos son
rulesets curados por Semgrep Inc. para los lenguajes del scope.

Uso:
    aios semgrep-scan --root . --config p/ci
    aios semgrep-scan --root . --fail-on high
    aios semgrep-scan --root . --format json

Si semgrep no está instalado · skip sin blocking (portabilidad Python-only).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from aios.core.external_scanner_base import (
    SEVERITY_ORDER, run_cli_capture, meets_threshold,
)


# Semgrep severity (ERROR/WARNING/INFO) → AIOS severity
_SEMGREP_SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    # semgrep también usa CRITICAL en algunos rulesets
    "CRITICAL": "CRITICAL",
}


@dataclass(frozen=True)
class SemgrepFinding:
    check_id: str
    severity: str  # CRITICAL|HIGH|MEDIUM|LOW
    path: str
    start_line: int
    message: str
    cwe: tuple[str, ...] = ()


@dataclass(frozen=True)
class SemgrepReport:
    root: str
    findings: list[SemgrepFinding]
    scanner_available: bool
    error: Optional[str] = None
    passed: bool = False
    fail_on_severity: Optional[str] = None
    violations: list[str] = field(default_factory=list)


def run_semgrep(root: Path, config: str = "p/ci",
                timeout_seconds: int = 300) -> dict:
    """Ejecuta `semgrep scan --json` con el config provisto."""
    cmd = ["semgrep", "scan", "--json", "--quiet", "--config", config,
           str(root)]
    # semgrep retorna 1 cuando encuentra findings · no es error
    cli = run_cli_capture(cmd, cwd=None, timeout_seconds=timeout_seconds,
                          accept_nonzero_exits={1})

    if not cli.available:
        return {"scanner_available": False, "error": cli.error}

    if cli.error and not cli.stdout:
        return {"scanner_available": True, "error": cli.error}

    try:
        return json.loads(cli.stdout) if cli.stdout else {}
    except json.JSONDecodeError as e:
        return {"scanner_available": True,
                "error": f"semgrep output no es JSON válido: {e}"}


def parse_semgrep_output(data: dict, root: str) -> SemgrepReport:
    """Convierte output semgrep JSON a SemgrepReport."""
    if not data.get("scanner_available", True):
        return SemgrepReport(
            root=root, findings=[], scanner_available=False,
            error=data.get("error", "semgrep no disponible"),
        )
    if "error" in data:
        return SemgrepReport(
            root=root, findings=[], scanner_available=True,
            error=data["error"],
        )

    findings: list[SemgrepFinding] = []
    for result in data.get("results", []):
        if not isinstance(result, dict):
            continue
        extra = result.get("extra", {}) or {}
        severity_raw = str(extra.get("severity", "INFO")).upper()
        severity = _SEMGREP_SEVERITY_MAP.get(severity_raw, "MEDIUM")

        metadata = extra.get("metadata", {}) or {}
        cwe_entries = metadata.get("cwe", [])
        if isinstance(cwe_entries, str):
            cwe_entries = [cwe_entries]
        cwes = tuple(str(c) for c in cwe_entries[:3])

        start = result.get("start", {}) or {}
        findings.append(SemgrepFinding(
            check_id=str(result.get("check_id", "unknown")),
            severity=severity,
            path=str(result.get("path", "")),
            start_line=int(start.get("line", 0) or 0),
            message=str(extra.get("message", ""))[:200],
            cwe=cwes,
        ))

    return SemgrepReport(
        root=root, findings=findings, scanner_available=True,
    )


def apply_gate(report: SemgrepReport,
               fail_on_severity: Optional[str]) -> SemgrepReport:
    """Aplica threshold · passed=False si hay findings >= umbral."""
    if report.error or not report.scanner_available:
        return SemgrepReport(
            root=report.root, findings=report.findings,
            scanner_available=report.scanner_available, error=report.error,
            passed=True, fail_on_severity=fail_on_severity, violations=[],
        )

    violations: list[str] = []
    for f in report.findings:
        if meets_threshold(f.severity, fail_on_severity):
            violations.append(
                f"{f.severity} · {f.check_id} · {f.path}:{f.start_line}"
            )

    return SemgrepReport(
        root=report.root, findings=report.findings,
        scanner_available=True, error=None,
        passed=len(violations) == 0,
        fail_on_severity=fail_on_severity, violations=violations,
    )


def format_human(report: SemgrepReport) -> str:
    out: list[str] = ["", "  Semgrep SAST · G-18 · scanner gate",
                      "  " + "-" * 68,
                      f"  Root          : {report.root}"]
    if not report.scanner_available:
        out.append(f"  semgrep avail : NO · {report.error}")
        out.append("  SKIPPED (no blocking)")
        out.append("")
        return "\n".join(out)
    if report.error:
        out.append(f"  ERROR · {report.error}")
        out.append("")
        return "\n".join(out)

    out.append(f"  Findings      : {len(report.findings)}")
    if report.fail_on_severity:
        out.append(f"  Fail threshold: {report.fail_on_severity}")
    out.append("")

    if report.findings:
        out.append("  By check_id:")
        for f in sorted(
            report.findings,
            key=lambda x: (-SEVERITY_ORDER.get(x.severity, 0), x.path)
        )[:30]:
            out.append(
                f"    · {f.severity:<8} {f.check_id} "
                f"{f.path}:{f.start_line}"
            )
        if len(report.findings) > 30:
            out.append(f"    ... +{len(report.findings) - 30} más")
        out.append("")

    out.append("  PASSED" if report.passed else f"  FAILED · {len(report.violations)} violation(s)")
    out.append("")
    return "\n".join(out)


def format_json(report: SemgrepReport) -> str:
    def ser(f: SemgrepFinding) -> dict:
        return {
            "check_id": f.check_id, "severity": f.severity,
            "path": f.path, "start_line": f.start_line,
            "message": f.message, "cwe": list(f.cwe),
        }

    return json.dumps({
        "passed": report.passed, "root": report.root,
        "scanner_available": report.scanner_available,
        "error": report.error,
        "fail_on_severity": report.fail_on_severity,
        "findings": [ser(f) for f in report.findings],
        "violations": report.violations,
    }, indent=2)
