"""Compliance mapping · tag findings (Mythos/Nemesis/embedded scanner)
a marcos regulatorios relevantes para AMX.

Marcos cubiertos:
- LFPDPPP  · Ley Federal de Proteccion de Datos Personales (Mexico)
- LGPDP    · Ley General de Proteccion de Datos Personales Sujetos Obligados
- PCI-DSS  · Payment Card Industry Data Security Standard (v4.0)
- SOX      · Sarbanes-Oxley (relevante por listaje NYSE/BMV)
- CFF-30   · Codigo Fiscal de la Federacion art. 30 (facturacion electronica)
- OWASP    · Top 10 2021 (referencia general · no regulatorio pero
             pedido por Miatech en politica amx-revenue-accounting)

Cada CWE tiene una lista de ComplianceTag. El agregador cuenta findings
por marco y genera reporte markdown.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .security_gate import Finding


@dataclass(frozen=True)
class ComplianceTag:
    framework: str       # ej. "PCI-DSS"
    requirement: str     # ej. "8.3.1"
    description: str     # ej. "Multi-factor auth for non-console admin"


# Mapping CWE → lista de ComplianceTag relevantes
# Nota: solo incluimos los tags mas relevantes · no es exhaustivo
_CWE_COMPLIANCE: dict[str, list[ComplianceTag]] = {
    "CWE-22": [
        ComplianceTag("PCI-DSS", "6.2.4", "Secure code · validate untrusted input (path traversal)"),
        ComplianceTag("OWASP", "A01:2021", "Broken Access Control"),
        ComplianceTag("LFPDPPP", "Art. 19", "Medidas de seguridad administrativas y tecnicas"),
    ],
    "CWE-78": [
        ComplianceTag("PCI-DSS", "6.2.4", "Secure code · command injection prevention"),
        ComplianceTag("OWASP", "A03:2021", "Injection"),
        ComplianceTag("SOX", "ITGC-AC3", "Application access · logical security controls"),
    ],
    "CWE-79": [
        ComplianceTag("PCI-DSS", "6.2.4", "Secure code · output encoding"),
        ComplianceTag("OWASP", "A03:2021", "Injection (XSS)"),
        ComplianceTag("LFPDPPP", "Art. 19", "Medidas de seguridad"),
    ],
    "CWE-89": [
        ComplianceTag("PCI-DSS", "6.2.4", "Secure code · parametrized queries"),
        ComplianceTag("OWASP", "A03:2021", "Injection (SQL)"),
        ComplianceTag("SOX", "ITGC-AC4", "Data access controls · segregation of duties"),
        ComplianceTag("LFPDPPP", "Art. 19", "Medidas de seguridad"),
    ],
    "CWE-287": [
        ComplianceTag("PCI-DSS", "8.2.1", "User authentication · strong cryptography"),
        ComplianceTag("PCI-DSS", "8.3.1", "Multi-factor auth non-console admin"),
        ComplianceTag("OWASP", "A07:2021", "Identification and Authentication Failures"),
        ComplianceTag("SOX", "ITGC-AC1", "Logical access · authentication"),
    ],
    "CWE-319": [
        ComplianceTag("PCI-DSS", "4.2.1", "TLS only for cardholder data transmission"),
        ComplianceTag("OWASP", "A02:2021", "Cryptographic Failures"),
        ComplianceTag("LFPDPPP", "Art. 19", "Cifrado de datos en transito"),
        ComplianceTag("CFF-30", "Fracc. IV", "Conservacion y seguridad de comprobantes"),
    ],
    "CWE-502": [
        ComplianceTag("PCI-DSS", "6.2.4", "Secure code · safe deserialization"),
        ComplianceTag("OWASP", "A08:2021", "Software and Data Integrity Failures"),
        ComplianceTag("SOX", "ITGC-CM1", "Change management · secure dev lifecycle"),
    ],
    "CWE-547": [
        ComplianceTag("PCI-DSS", "6.4.3", "Production-ready configs · no hardcoded secrets"),
        ComplianceTag("LFPDPPP", "Art. 19", "Medidas administrativas"),
    ],
    "CWE-601": [
        ComplianceTag("OWASP", "A01:2021", "Broken Access Control (open redirect)"),
        ComplianceTag("PCI-DSS", "6.2.4", "Secure code · URL validation"),
    ],
    "CWE-611": [
        ComplianceTag("PCI-DSS", "6.2.4", "Secure code · XXE prevention"),
        ComplianceTag("OWASP", "A05:2021", "Security Misconfiguration"),
        ComplianceTag("CFF-30", "Fracc. IV", "Integridad de XMLs SAT/CFDI"),
    ],
    "CWE-798": [
        ComplianceTag("PCI-DSS", "8.3.2", "Passwords not hardcoded"),
        ComplianceTag("PCI-DSS", "6.4.3", "Secrets management"),
        ComplianceTag("OWASP", "A07:2021", "Hardcoded credentials"),
        ComplianceTag("SOX", "ITGC-AC1", "Logical access · credential management"),
        ComplianceTag("LFPDPPP", "Art. 19", "Medidas de seguridad · credenciales"),
    ],
    "CWE-200": [
        ComplianceTag("LFPDPPP", "Art. 19", "Confidencialidad de datos personales"),
        ComplianceTag("LGPDP", "Art. 31", "Medidas de seguridad sujetos obligados"),
        ComplianceTag("PCI-DSS", "3.5.1", "Mask PAN when displayed"),
    ],
}


def tags_for(cwe: str) -> list[ComplianceTag]:
    """Retorna los ComplianceTags relevantes para un CWE dado."""
    return list(_CWE_COMPLIANCE.get(cwe, []))


def group_findings_by_framework(
    findings: Iterable[Finding],
) -> dict[str, list[tuple[Finding, ComplianceTag]]]:
    """Agrupa findings por marco regulatorio via CWE mapping."""
    groups: dict[str, list[tuple[Finding, ComplianceTag]]] = {}
    for f in findings:
        for tag in tags_for(f.cwe):
            groups.setdefault(tag.framework, []).append((f, tag))
    return groups


def render_compliance_report(
    findings: Iterable[Finding],
    project_name: str = "project",
) -> str:
    """Markdown consolidado · findings agrupados por marco + recomendacion."""
    findings_list = list(findings)
    groups = group_findings_by_framework(findings_list)

    lines = [
        f"# Compliance Report · {project_name}",
        "",
        f"**Total findings:** {len(findings_list)}",
        f"**Frameworks impactados:** {len(groups)}",
        "",
    ]

    if not groups:
        lines.append("_Sin findings mapeados a marcos regulatorios._")
        return "\n".join(lines)

    # Ordenar por framework name
    for framework in sorted(groups.keys()):
        items = groups[framework]
        lines.append(f"## {framework}")
        lines.append("")
        lines.append(f"**{len(items)} findings afectan este marco.**")
        lines.append("")
        lines.append("| Requirement | Description | Severity | CWE | File:Line |")
        lines.append("|---|---|---|---|---|")
        for finding, tag in items[:20]:  # cap 20 por marco
            lines.append(
                f"| {tag.requirement} | {tag.description} | "
                f"{finding.severity} | {finding.cwe} | "
                f"{finding.file}:{finding.line} |"
            )
        if len(items) > 20:
            lines.append(f"| _... y {len(items) - 20} mas ..._ | | | | |")
        lines.append("")

    # Summary table cross-framework
    lines.append("## Resumen")
    lines.append("")
    lines.append("| Framework | Findings | Severidad top |")
    lines.append("|---|---|---|")
    for framework in sorted(groups.keys()):
        items = groups[framework]
        severities = [f.severity for f, _ in items]
        top_sev = next(
            (s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if s in severities),
            "INFO",
        )
        lines.append(f"| {framework} | {len(items)} | {top_sev} |")

    return "\n".join(lines)
