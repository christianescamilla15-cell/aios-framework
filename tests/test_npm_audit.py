"""Tests · v3.6.4 · G-17 npm audit supply-chain wrap."""
from __future__ import annotations

import json
from pathlib import Path

from aios.core.npm_audit import (
    parse_npm_audit_output,
    apply_gate,
    format_human,
    format_json,
    NpmVulnerability,
)


def _sample_audit_output(severity: str = "high",
                         package: str = "lodash",
                         direct: bool = True) -> dict:
    """Construye output sintético estilo npm audit v7+."""
    return {
        "vulnerabilities": {
            package: {
                "name": package,
                "severity": severity,
                "isDirect": direct,
                "via": [
                    {"source": 1234, "url": "https://github.com/advisories/GHSA-xxx-yyy",
                     "name": package}
                ],
                "fixAvailable": True,
                "range": ">=0.0.0 <4.17.21",
            }
        },
        "metadata": {
            "vulnerabilities": {
                "total": 1, "critical": 0, "high": 1, "moderate": 0, "low": 0,
            },
            "totalDependencies": 42,
        },
    }


def test_parse_npm_audit_extracts_vulnerability():
    """Parser extrae nombre + severity + direct flag correctamente."""
    data = _sample_audit_output(severity="critical", package="axios")
    report = parse_npm_audit_output(data, root="/tmp/proj")

    assert len(report.vulnerabilities) == 1
    v = report.vulnerabilities[0]
    assert v.package == "axios"
    assert v.severity == "CRITICAL"
    assert v.direct is True
    assert v.fix_available is True
    assert report.total_packages_scanned == 42
    assert report.npm_available is True


def test_parse_npm_audit_severity_mapping():
    """Mapping npm (moderate) → AIOS (MEDIUM) · 'info' → LOW."""
    data = {
        "vulnerabilities": {
            "pkg-a": {"name": "pkg-a", "severity": "moderate", "isDirect": False, "via": []},
            "pkg-b": {"name": "pkg-b", "severity": "info", "isDirect": False, "via": []},
        },
        "metadata": {"totalDependencies": 10},
    }
    report = parse_npm_audit_output(data, root="/tmp/p")
    severities = {v.package: v.severity for v in report.vulnerabilities}
    assert severities["pkg-a"] == "MEDIUM"
    assert severities["pkg-b"] == "LOW"


def test_apply_gate_fail_on_high_blocks_critical_and_high():
    """Gate fail-on=high bloquea HIGH + CRITICAL · deja pasar MEDIUM/LOW."""
    data = {
        "vulnerabilities": {
            "a": {"name": "a", "severity": "critical", "isDirect": True, "via": []},
            "b": {"name": "b", "severity": "high", "isDirect": False, "via": []},
            "c": {"name": "c", "severity": "moderate", "isDirect": False, "via": []},
        },
        "metadata": {"totalDependencies": 50},
    }
    report = parse_npm_audit_output(data, root="/tmp/p")
    report = apply_gate(report, fail_on_severity="high")
    assert report.passed is False
    # 2 violations: critical + high
    assert len(report.violations) == 2


def test_apply_gate_no_threshold_always_passes():
    """Sin --fail-on · reporta pero nunca falla."""
    data = _sample_audit_output(severity="critical")
    report = parse_npm_audit_output(data, root="/tmp/p")
    report = apply_gate(report, fail_on_severity=None)
    assert report.passed is True
    assert report.violations == []


def test_apply_gate_passes_when_all_below_threshold():
    """Fail-on=critical · HIGH no dispara."""
    data = _sample_audit_output(severity="high")
    report = parse_npm_audit_output(data, root="/tmp/p")
    report = apply_gate(report, fail_on_severity="critical")
    assert report.passed is True


def test_npm_not_available_skips_without_blocking():
    """Si npm no está · passed=True · skip sin blocking."""
    data = {"npm_available": False, "error": "npm not found"}
    report = parse_npm_audit_output(data, root="/tmp/p")
    report = apply_gate(report, fail_on_severity="high")
    # Skip no bloquea pipeline
    assert report.passed is True
    assert report.npm_available is False


def test_format_human_includes_threshold_and_counts():
    data = _sample_audit_output(severity="critical", package="minimatch")
    report = parse_npm_audit_output(data, root="/tmp/proj")
    report = apply_gate(report, fail_on_severity="high")
    out = format_human(report)
    assert "minimatch" in out
    assert "CRITICAL" in out
    assert "FAILED" in out
    assert "Fail threshold" in out


def test_format_json_serializable():
    data = _sample_audit_output(severity="high", package="lodash")
    report = parse_npm_audit_output(data, root="/tmp/proj")
    report = apply_gate(report, fail_on_severity="low")
    s = format_json(report)
    parsed = json.loads(s)
    assert parsed["passed"] is False
    assert parsed["vulnerabilities"][0]["package"] == "lodash"
    assert parsed["vulnerabilities"][0]["severity"] == "HIGH"


def test_parse_npm_audit_handles_empty_vulnerabilities():
    """Proyecto clean · vulns={} · passed por default."""
    data = {"vulnerabilities": {}, "metadata": {"totalDependencies": 100}}
    report = parse_npm_audit_output(data, root="/tmp/p")
    report = apply_gate(report, fail_on_severity="low")
    assert len(report.vulnerabilities) == 0
    assert report.total_packages_scanned == 100
    assert report.passed is True


def test_parse_npm_audit_advisories_capped_at_5():
    """Evita output ruidoso · advisories cap en 5 por package."""
    data = {
        "vulnerabilities": {
            "pkg": {
                "name": "pkg",
                "severity": "high",
                "isDirect": True,
                "via": [{"source": i, "name": "pkg"} for i in range(20)],
            }
        },
        "metadata": {"totalDependencies": 1},
    }
    report = parse_npm_audit_output(data, root="/tmp/p")
    v = report.vulnerabilities[0]
    assert len(v.advisories) == 5
