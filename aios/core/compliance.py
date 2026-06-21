"""Compliance mapping · tag findings (Mythos/Nemesis/embedded scanner)
a marcos regulatorios relevantes para ACME.

Marcos cubiertos:
- LFPDPPP  · Ley Federal de Proteccion de Datos Personales (Mexico)
- LGPDP    · Ley General de Proteccion de Datos Personales Sujetos Obligados
- PCI-DSS  · Payment Card Industry Data Security Standard (v4.0)
- SOX      · Sarbanes-Oxley (relevante por listaje NYSE/BMV)
- CFF-30   · Codigo Fiscal de la Federacion art. 30 (facturacion electronica)
- OWASP    · Top 10 2021 (referencia general · no regulatorio pero
             pedido por Miatech en politica acme-finance_operations)

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


def render_compliance_report_html(
    findings: Iterable[Finding],
    project_name: str = "project",
) -> str:
    """HTML printable con tabla por marco · convertible a PDF."""
    findings_list = list(findings)
    groups = group_findings_by_framework(findings_list)
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    head = (
        '<!doctype html><html><head><meta charset="utf-8">'
        f'<title>Compliance · {project_name}</title>'
        '<style>'
        '@page{margin:2cm;size:A4}'
        'body{font-family:-apple-system,"Segoe UI",Arial,sans-serif;color:#111;max-width:900px;margin:20px auto;padding:20px}'
        'h1{color:#0b4f6c;border-bottom:2px solid #0b4f6c;padding-bottom:8px}'
        'h2{color:#0b4f6c;margin-top:28px}'
        '.meta{color:#555;font-size:13px;margin-bottom:24px}'
        '.summary-box{background:#f5f9fb;border-left:4px solid #0b4f6c;padding:12px;margin-bottom:24px}'
        'table{width:100%;border-collapse:collapse;margin:10px 0;font-size:12px;page-break-inside:avoid}'
        'th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #ddd;vertical-align:top}'
        'th{background:#e9eef2;font-weight:600;font-size:11px;text-transform:uppercase}'
        '.sev-CRITICAL{color:#c00;font-weight:700}'
        '.sev-HIGH{color:#e67e22;font-weight:600}'
        '.sev-MEDIUM{color:#b58900}'
        '.sev-LOW{color:#555}'
        'code{font-family:Consolas,Monaco,monospace;font-size:11px;background:#f0f0f0;padding:1px 4px;border-radius:2px}'
        '.footer{margin-top:48px;padding-top:16px;border-top:1px solid #ccc;font-size:11px;color:#777}'
        '</style></head><body>'
        f'<h1>Compliance Report · {project_name}</h1>'
        f'<div class="meta">Generado · {ts} · AIOS compliance module</div>'
        '<div class="summary-box">'
        f'<strong>Total findings:</strong> {len(findings_list)}<br>'
        f'<strong>Frameworks impactados:</strong> {len(groups)}'
        '</div>'
    )
    if not groups:
        return head + "<p><em>Sin findings mapeados.</em></p></body></html>"

    parts: list[str] = [head]
    for framework in sorted(groups.keys()):
        items = groups[framework]
        parts.append(f"<h2>{framework}</h2>")
        parts.append(f"<p><strong>{len(items)} findings</strong> afectan este marco.</p>")
        parts.append("<table><thead><tr><th>Requirement</th><th>Description</th><th>Sev</th><th>CWE</th><th>File:Line</th></tr></thead><tbody>")
        for finding, tag in items[:50]:
            parts.append(
                f'<tr><td>{tag.requirement}</td><td>{tag.description}</td>'
                f'<td class="sev-{finding.severity}">{finding.severity}</td>'
                f'<td>{finding.cwe}</td>'
                f'<td><code>{finding.file}:{finding.line}</code></td></tr>'
            )
        if len(items) > 50:
            parts.append(f'<tr><td colspan="5"><em>... y {len(items) - 50} mas ...</em></td></tr>')
        parts.append("</tbody></table>")

    parts.append("<h2>Resumen</h2>")
    parts.append("<table><thead><tr><th>Framework</th><th>Findings</th><th>Severidad top</th></tr></thead><tbody>")
    for framework in sorted(groups.keys()):
        items = groups[framework]
        severities = [f.severity for f, _ in items]
        top_sev = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if s in severities), "INFO")
        parts.append(
            f'<tr><td>{framework}</td><td>{len(items)}</td>'
            f'<td class="sev-{top_sev}">{top_sev}</td></tr>'
        )
    parts.append("</tbody></table>")
    parts.append(
        '<div class="footer">'
        'Generado por AIOS compliance module · marcos ACME · LFPDPPP · '
        'LGPDP · PCI-DSS v4.0 · SOX · CFF art. 30 · OWASP Top 10 2021. '
        'Requirements son referencias orientativas · validar con compliance '
        'officer antes de auditoria.</div></body></html>'
    )
    return "".join(parts)


def render_compliance_report_pdf(
    findings: Iterable[Finding],
    output_path: Path,
    project_name: str = "project",
) -> tuple[bool, str]:
    """Convierte a PDF via weasyprint · fallback a HTML si no esta
    instalado. Retorna (ok, mensaje)."""
    html = render_compliance_report_html(findings, project_name)
    try:
        from weasyprint import HTML  # type: ignore
        HTML(string=html).write_pdf(str(output_path))
        return True, f"PDF generado · {output_path}"
    except ImportError:
        html_path = output_path.with_suffix(".html")
        html_path.write_text(html, encoding="utf-8")
        return False, (
            f"weasyprint no disponible · HTML en {html_path}. "
            "Instala con `pip install weasyprint` o print-to-PDF "
            "desde el browser."
        )
    except Exception as exc:  # noqa: BLE001
        html_path = output_path.with_suffix(".html")
        html_path.write_text(html, encoding="utf-8")
        return False, f"weasyprint fallo: {exc} · HTML en {html_path}"


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
