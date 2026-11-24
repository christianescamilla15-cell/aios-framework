"""Ensemble OSS scanner · v2.6.0

Wrapper que corre en serie las herramientas OSS ortogonales disponibles y
normaliza el output a EnsembleFinding. Literatura (EASE 2024) muestra
que ensemble bate +181% a single-tool recall.

Tools soportados (graceful-skip si no estan instalados):
- semgrep       · code · multi-lenguaje · reglas propias + registry
- gitleaks      · secrets leak · alto recall 86-88%
- trufflehog    · secrets · incluye deep-entropy
- bandit        · python security
- checkov       · IaC (TF · CFN · Helm · Dockerfile)
- trivy         · SBOM + CVE + secrets + IaC
- codeql        · taint flow · requires pre-built DB

CLI:
    aios ensemble --root . --tools semgrep,gitleaks

Output: per-tool summary + JSON consolidado opcional (--format json).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


_SUPPORTED_TOOLS = ("semgrep", "gitleaks", "trufflehog", "bandit",
                    "checkov", "trivy", "codeql")


@dataclass
class EnsembleFinding:
    tool: str
    rule_id: str
    severity: str  # CRITICAL · HIGH · MEDIUM · LOW · INFO
    file: str
    line: int
    message: str
    cwe: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EnsembleReport:
    root: str
    tools_run: list[str] = field(default_factory=list)
    tools_skipped: dict[str, str] = field(default_factory=dict)
    per_tool_counts: dict[str, int] = field(default_factory=dict)
    findings: list[EnsembleFinding] = field(default_factory=list)

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "tools_run": self.tools_run,
            "tools_skipped": self.tools_skipped,
            "per_tool_counts": self.per_tool_counts,
            "by_severity": self.by_severity(),
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Tool runners · cada uno retorna list[EnsembleFinding]
# ---------------------------------------------------------------------------

def _run_semgrep(root: Path, timeout: int = 600) -> list[EnsembleFinding]:
    """Ejecuta `semgrep --config=auto --json` sobre root."""
    findings: list[EnsembleFinding] = []
    try:
        proc = subprocess.run(
            ["semgrep", "--config=auto", "--json", "--quiet",
             "--error", "--metrics=off", str(root)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return [EnsembleFinding("semgrep", "RUNTIME-ERROR", "INFO",
                                str(root), 0, f"semgrep no corrio: {e}")]
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return findings
    for res in data.get("results", []):
        sev_raw = (res.get("extra", {}).get("severity") or "INFO").upper()
        sev = {
            "ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW",
        }.get(sev_raw, sev_raw)
        findings.append(EnsembleFinding(
            tool="semgrep",
            rule_id=res.get("check_id", "unknown"),
            severity=sev,
            file=res.get("path", ""),
            line=res.get("start", {}).get("line", 0),
            message=res.get("extra", {}).get("message", "")[:300],
            cwe=",".join(res.get("extra", {}).get("metadata", {})
                         .get("cwe", [])[:3]),
            extra={"fix": res.get("extra", {}).get("fix", "")},
        ))
    return findings


def _run_gitleaks(root: Path, timeout: int = 300) -> list[EnsembleFinding]:
    findings: list[EnsembleFinding] = []
    try:
        proc = subprocess.run(
            ["gitleaks", "detect", "--source", str(root), "--report-format",
             "json", "--no-banner", "--redact", "--report-path", "-",
             "--exit-code", "0"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return [EnsembleFinding("gitleaks", "RUNTIME-ERROR", "INFO",
                                str(root), 0, f"gitleaks no corrio: {e}")]
    # gitleaks puede imprimir progreso a stderr · stdout tiene el JSON
    try:
        # gitleaks JSON output es un array
        output = proc.stdout.strip()
        if not output or output == "null":
            return findings
        data = json.loads(output)
    except json.JSONDecodeError:
        return findings
    for res in data or []:
        findings.append(EnsembleFinding(
            tool="gitleaks",
            rule_id=res.get("RuleID", "unknown"),
            severity="HIGH",
            file=res.get("File", ""),
            line=res.get("StartLine", 0),
            message=res.get("Description", "")[:200],
            cwe="CWE-798",
            extra={"match": res.get("Match", "")[:80]},
        ))
    return findings


def _run_trufflehog(root: Path, timeout: int = 300) -> list[EnsembleFinding]:
    findings: list[EnsembleFinding] = []
    try:
        proc = subprocess.run(
            ["trufflehog", "filesystem", str(root), "--json",
             "--no-verification"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return [EnsembleFinding("trufflehog", "RUNTIME-ERROR", "INFO",
                                str(root), 0, f"trufflehog no corrio: {e}")]
    # trufflehog imprime un JSON por linea (JSONL)
    for line in (proc.stdout or "").splitlines():
        try:
            res = json.loads(line)
        except json.JSONDecodeError:
            continue
        meta = res.get("SourceMetadata", {}).get("Data", {}).get(
            "Filesystem", {}) or {}
        findings.append(EnsembleFinding(
            tool="trufflehog",
            rule_id=res.get("DetectorName", "unknown"),
            severity="HIGH",
            file=meta.get("file", ""),
            line=meta.get("line", 0),
            message=f"Secret: {res.get('DetectorName','')} · "
                    f"verified={res.get('Verified',False)}",
            cwe="CWE-798",
        ))
    return findings


def _run_bandit(root: Path, timeout: int = 300) -> list[EnsembleFinding]:
    findings: list[EnsembleFinding] = []
    try:
        proc = subprocess.run(
            ["bandit", "-r", str(root), "-f", "json", "-q",
             "--exit-zero"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return [EnsembleFinding("bandit", "RUNTIME-ERROR", "INFO",
                                str(root), 0, f"bandit no corrio: {e}")]
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return findings
    sev_map = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    for res in data.get("results", []):
        findings.append(EnsembleFinding(
            tool="bandit",
            rule_id=res.get("test_id", "unknown"),
            severity=sev_map.get(res.get("issue_severity", "LOW").upper(), "LOW"),
            file=res.get("filename", ""),
            line=res.get("line_number", 0),
            message=res.get("issue_text", "")[:200],
            cwe=str(res.get("issue_cwe", {}).get("id", "")),
        ))
    return findings


def _run_checkov(root: Path, timeout: int = 600) -> list[EnsembleFinding]:
    findings: list[EnsembleFinding] = []
    try:
        proc = subprocess.run(
            ["checkov", "-d", str(root), "-o", "json", "--quiet",
             "--soft-fail"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return [EnsembleFinding("checkov", "RUNTIME-ERROR", "INFO",
                                str(root), 0, f"checkov no corrio: {e}")]
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return findings
    # Checkov output puede ser lista o dict con key "results"
    if isinstance(data, list):
        iterable = data
    else:
        iterable = [data]
    for report in iterable:
        for res in report.get("results", {}).get("failed_checks", []):
            findings.append(EnsembleFinding(
                tool="checkov",
                rule_id=res.get("check_id", "unknown"),
                severity="MEDIUM",
                file=res.get("file_path", ""),
                line=(res.get("file_line_range", [0])[0] or 0),
                message=res.get("check_name", "")[:200],
                cwe="",
            ))
    return findings


def _run_trivy(root: Path, timeout: int = 600) -> list[EnsembleFinding]:
    findings: list[EnsembleFinding] = []
    try:
        proc = subprocess.run(
            ["trivy", "fs", "--format", "json", "--quiet",
             "--scanners", "vuln,secret,misconfig", str(root)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return [EnsembleFinding("trivy", "RUNTIME-ERROR", "INFO",
                                str(root), 0, f"trivy no corrio: {e}")]
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return findings
    sev_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH",
               "MEDIUM": "MEDIUM", "LOW": "LOW", "UNKNOWN": "INFO"}
    for res in data.get("Results", []):
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            findings.append(EnsembleFinding(
                tool="trivy",
                rule_id=v.get("VulnerabilityID", "unknown"),
                severity=sev_map.get(v.get("Severity", "UNKNOWN"), "INFO"),
                file=target,
                line=0,
                message=v.get("Title", "")[:200],
                cwe=",".join(v.get("CweIDs", [])[:3]),
            ))
        for s in res.get("Secrets", []) or []:
            findings.append(EnsembleFinding(
                tool="trivy",
                rule_id=s.get("RuleID", "unknown"),
                severity=sev_map.get(s.get("Severity", "UNKNOWN"), "INFO"),
                file=target,
                line=s.get("StartLine", 0),
                message=s.get("Title", "")[:200],
                cwe="CWE-798",
            ))
    return findings


_RUNNERS = {
    "semgrep": _run_semgrep,
    "gitleaks": _run_gitleaks,
    "trufflehog": _run_trufflehog,
    "bandit": _run_bandit,
    "checkov": _run_checkov,
    "trivy": _run_trivy,
}


class EnsembleScanner:
    """Coordina N tools OSS · retorna un EnsembleReport consolidado."""

    def __init__(self, root: Path, tools: Optional[list[str]] = None,
                 timeout_per_tool: int = 600):
        self.root = Path(root).resolve()
        self.tools = tools or self._auto_detect()
        self.timeout = timeout_per_tool

    def _auto_detect(self) -> list[str]:
        return [t for t in _SUPPORTED_TOOLS if shutil.which(t)]

    def scan(self) -> EnsembleReport:
        report = EnsembleReport(root=str(self.root))
        for tool in self.tools:
            if tool not in _RUNNERS:
                report.tools_skipped[tool] = "no runner implementado"
                continue
            if not shutil.which(tool):
                report.tools_skipped[tool] = "binary no encontrado en PATH"
                continue
            runner = _RUNNERS[tool]
            try:
                findings = runner(self.root, self.timeout)
            except Exception as exc:  # noqa: BLE001
                report.tools_skipped[tool] = f"error: {exc}"
                continue
            report.tools_run.append(tool)
            report.per_tool_counts[tool] = len(findings)
            report.findings.extend(findings)
        return report


def run_ensemble(root: Path,
                 tools: Optional[list[str]] = None) -> EnsembleReport:
    """Convenience · alias del constructor + scan()."""
    return EnsembleScanner(root, tools=tools).scan()
