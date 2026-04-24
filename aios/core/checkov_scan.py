"""v3.6.5 · G-20 · Checkov IaC scan wrap.

Envuelve `checkov -d . -o json` para IaC misconfigurations (Terraform ·
CloudFormation · Kubernetes · CDK · ARM · Helm).

Uso:
    aios iac-scan --root infra/
    aios iac-scan --root infra/ --framework cloudformation
    aios iac-scan --root infra/ --fail-on high
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from aios.core.external_scanner_base import (
    SEVERITY_ORDER, run_cli_capture, meets_threshold,
)


# Checkov severity (HIGH/MEDIUM/LOW · a veces CRITICAL) ya es AIOS-compatible
_CHECKOV_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    # algunos checks no tienen severity asignado
    "INFO": "LOW",
    "NONE": "LOW",
}


@dataclass(frozen=True)
class CheckovFinding:
    check_id: str  # CKV_AWS_X o CKV_K8S_X
    severity: str
    resource: str
    file_path: str
    file_line_range: tuple[int, int]
    check_name: str
    guideline: str = ""


@dataclass(frozen=True)
class CheckovReport:
    root: str
    findings: list[CheckovFinding]
    scanner_available: bool
    framework: str = "all"
    passed_count: int = 0
    error: Optional[str] = None
    passed: bool = False
    fail_on_severity: Optional[str] = None
    violations: list[str] = field(default_factory=list)


def run_checkov(root: Path, framework: str = "all",
                timeout_seconds: int = 600) -> dict:
    """Ejecuta `checkov -d <root> -o json --framework <framework>`."""
    cmd = ["checkov", "-d", str(root), "-o", "json", "--quiet"]
    if framework and framework != "all":
        cmd.extend(["--framework", framework])
    # checkov retorna 1 cuando encuentra failed_checks · no es error real
    cli = run_cli_capture(cmd, timeout_seconds=timeout_seconds,
                          accept_nonzero_exits={1})

    if not cli.available:
        return {"scanner_available": False, "error": cli.error}

    if cli.error and not cli.stdout:
        return {"scanner_available": True, "error": cli.error}

    try:
        # checkov puede retornar array (multi-framework) o objeto single
        parsed = json.loads(cli.stdout) if cli.stdout else {}
        if isinstance(parsed, list):
            # merge results into single pseudo-report
            merged_failed: list[dict] = []
            merged_passed = 0
            for item in parsed:
                if isinstance(item, dict):
                    results = item.get("results", {})
                    merged_failed.extend(results.get("failed_checks", []))
                    merged_passed += len(results.get("passed_checks", []))
            return {"results": {"failed_checks": merged_failed,
                                "passed_checks_count": merged_passed}}
        return parsed
    except json.JSONDecodeError as e:
        return {"scanner_available": True,
                "error": f"checkov output no es JSON válido: {e}"}


def parse_checkov_output(data: dict, root: str,
                         framework: str = "all") -> CheckovReport:
    """Convierte output checkov JSON a CheckovReport.

    Formato checkov:
        {
          "results": {
            "passed_checks": [...],
            "failed_checks": [
              {
                "check_id": "CKV_AWS_X",
                "check_name": "Ensure ...",
                "severity": "HIGH",
                "resource": "aws_s3_bucket.my_bucket",
                "file_path": "/main.tf",
                "file_line_range": [10, 20],
                "guideline": "https://..."
              }
            ]
          }
        }
    """
    if not data.get("scanner_available", True):
        return CheckovReport(root=root, findings=[], scanner_available=False,
                             framework=framework,
                             error=data.get("error"))
    if "error" in data:
        return CheckovReport(root=root, findings=[], scanner_available=True,
                             framework=framework, error=data["error"])

    results = data.get("results", {}) or {}
    failed = results.get("failed_checks", []) or []
    passed_count_raw = results.get("passed_checks_count")
    if passed_count_raw is None:
        passed_count_raw = len(results.get("passed_checks", []) or [])

    findings: list[CheckovFinding] = []
    for f in failed:
        if not isinstance(f, dict):
            continue
        severity_raw = str(f.get("severity") or "MEDIUM").upper()
        severity = _CHECKOV_SEVERITY_MAP.get(severity_raw, "MEDIUM")
        line_range = f.get("file_line_range", [0, 0])
        if not isinstance(line_range, list) or len(line_range) < 2:
            line_range = [0, 0]
        findings.append(CheckovFinding(
            check_id=str(f.get("check_id", "unknown")),
            severity=severity,
            resource=str(f.get("resource", "")),
            file_path=str(f.get("file_path", "")),
            file_line_range=(int(line_range[0] or 0), int(line_range[1] or 0)),
            check_name=str(f.get("check_name", ""))[:150],
            guideline=str(f.get("guideline", ""))[:200],
        ))

    return CheckovReport(
        root=root, findings=findings, scanner_available=True,
        framework=framework, passed_count=int(passed_count_raw),
    )


def apply_gate(report: CheckovReport,
               fail_on_severity: Optional[str]) -> CheckovReport:
    if report.error or not report.scanner_available:
        return CheckovReport(
            root=report.root, findings=report.findings,
            scanner_available=report.scanner_available,
            framework=report.framework, passed_count=report.passed_count,
            error=report.error, passed=True,
            fail_on_severity=fail_on_severity, violations=[],
        )

    violations: list[str] = []
    for f in report.findings:
        if meets_threshold(f.severity, fail_on_severity):
            violations.append(
                f"{f.severity} · {f.check_id} · {f.resource} "
                f"{f.file_path}:{f.file_line_range[0]}"
            )

    return CheckovReport(
        root=report.root, findings=report.findings, scanner_available=True,
        framework=report.framework, passed_count=report.passed_count,
        error=None, passed=len(violations) == 0,
        fail_on_severity=fail_on_severity, violations=violations,
    )


def format_human(report: CheckovReport) -> str:
    out: list[str] = ["", "  Checkov IaC · G-20 · misconfig gate",
                      "  " + "-" * 68,
                      f"  Root          : {report.root}",
                      f"  Framework     : {report.framework}"]
    if not report.scanner_available:
        out.append(f"  checkov avail : NO · {report.error}")
        out.append("  SKIPPED (no blocking)")
        out.append("")
        return "\n".join(out)
    if report.error:
        out.append(f"  ERROR · {report.error}")
        out.append("")
        return "\n".join(out)

    out.append(f"  Passed        : {report.passed_count}")
    out.append(f"  Failed        : {len(report.findings)}")
    if report.fail_on_severity:
        out.append(f"  Fail threshold: {report.fail_on_severity}")
    out.append("")

    if report.findings:
        out.append("  Top 25 failed by severity:")
        for f in sorted(
            report.findings,
            key=lambda x: (-SEVERITY_ORDER.get(x.severity, 0), x.check_id)
        )[:25]:
            out.append(
                f"    · {f.severity:<8} {f.check_id} {f.resource} "
                f"({f.file_path}:{f.file_line_range[0]})"
            )
        if len(report.findings) > 25:
            out.append(f"    ... +{len(report.findings) - 25} más")
        out.append("")

    out.append("  PASSED" if report.passed
               else f"  FAILED · {len(report.violations)} violation(s)")
    out.append("")
    return "\n".join(out)


def format_json(report: CheckovReport) -> str:
    def ser(f: CheckovFinding) -> dict:
        return {
            "check_id": f.check_id, "severity": f.severity,
            "resource": f.resource, "file_path": f.file_path,
            "file_line_range": list(f.file_line_range),
            "check_name": f.check_name, "guideline": f.guideline,
        }

    return json.dumps({
        "passed": report.passed, "root": report.root,
        "framework": report.framework,
        "passed_count": report.passed_count,
        "scanner_available": report.scanner_available,
        "error": report.error,
        "fail_on_severity": report.fail_on_severity,
        "findings": [ser(f) for f in report.findings],
        "violations": report.violations,
    }, indent=2)
