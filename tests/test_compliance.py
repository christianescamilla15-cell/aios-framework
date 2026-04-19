"""Tests · compliance mapping · findings → marcos regulatorios."""

from __future__ import annotations

from pathlib import Path

import pytest

from aios.core.compliance import (
    ComplianceTag,
    group_findings_by_framework,
    render_compliance_report,
    tags_for,
)
from aios.core.security_gate import Finding


def _f(cwe: str, severity: str = "HIGH") -> Finding:
    return Finding(
        cwe=cwe, severity=severity, rule_id=f"R-{cwe}",
        file="x.py", line=1, snippet="",
    )


def test_tags_for_known_cwe():
    tags = tags_for("CWE-89")
    assert len(tags) > 0
    assert any(t.framework == "PCI-DSS" for t in tags)
    assert any(t.framework == "OWASP" for t in tags)


def test_tags_for_unknown_cwe_empty():
    assert tags_for("CWE-9999999") == []


def test_group_by_framework_sql_injection():
    groups = group_findings_by_framework([_f("CWE-89"), _f("CWE-89")])
    assert "PCI-DSS" in groups
    assert "OWASP" in groups
    # 2 findings x 4 tags = cada framework deberia tener 2 entries
    assert len(groups["PCI-DSS"]) == 2


def test_group_by_framework_separates_cwes():
    groups = group_findings_by_framework([_f("CWE-89"), _f("CWE-611")])
    # Ambos tocan PCI-DSS pero con distintos requirements
    assert "PCI-DSS" in groups
    reqs = {tag.requirement for _, tag in groups["PCI-DSS"]}
    assert len(reqs) >= 1


def test_render_empty_report():
    md = render_compliance_report([])
    assert "Total findings:** 0" in md
    assert "Sin findings" in md


def test_render_compliance_report_includes_frameworks():
    findings = [_f("CWE-89", "CRITICAL"), _f("CWE-798", "CRITICAL")]
    md = render_compliance_report(findings, project_name="test")

    assert "# Compliance Report · test" in md
    assert "Total findings:** 2" in md
    assert "## PCI-DSS" in md
    assert "## OWASP" in md
    assert "## Resumen" in md


def test_compliance_tag_fields():
    tags = tags_for("CWE-798")
    hardcoded_pci = next((t for t in tags if t.framework == "PCI-DSS"), None)
    assert hardcoded_pci is not None
    assert hardcoded_pci.requirement  # non-empty
    assert hardcoded_pci.description  # non-empty


def test_amx_specific_frameworks_present():
    """Verifica que marcos AMX-specific esten mapeados."""
    # Al menos un CWE debe mapear a LFPDPPP (Mexico data protection)
    all_frameworks = set()
    for cwe in ("CWE-22", "CWE-79", "CWE-89", "CWE-319", "CWE-798"):
        for tag in tags_for(cwe):
            all_frameworks.add(tag.framework)
    assert "LFPDPPP" in all_frameworks
    assert "CFF-30" in all_frameworks  # facturacion electronica
