"""Tests · v3.6.5 · G-19 Trivy container/fs scan wrap."""
from __future__ import annotations

import json

from aios.core.trivy_scan import (
    parse_trivy_output, apply_gate, format_human, format_json,
)


def _sample_trivy_output(severity: str = "HIGH",
                          vuln_id: str = "CVE-2024-1234",
                          pkg: str = "openssl"):
    """Output sintético estilo trivy image --format json."""
    return {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "alpine:3.15 (alpine 3.15.0)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": vuln_id,
                        "Severity": severity,
                        "PkgName": pkg,
                        "InstalledVersion": "1.1.1k",
                        "FixedVersion": "1.1.1l",
                        "Title": "OpenSSL heap overflow",
                    }
                ]
            }
        ]
    }


def test_parse_trivy_extracts_vulnerability():
    data = _sample_trivy_output(severity="CRITICAL", vuln_id="CVE-2024-0001")
    report = parse_trivy_output(data, target="alpine:3.15")
    assert len(report.vulnerabilities) == 1
    v = report.vulnerabilities[0]
    assert v.vuln_id == "CVE-2024-0001"
    assert v.severity == "CRITICAL"
    assert v.package == "openssl"
    assert v.fixed_version == "1.1.1l"


def test_parse_trivy_severity_unknown_maps_to_low():
    data = {
        "Results": [{
            "Target": "img",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-X", "Severity": "UNKNOWN",
                 "PkgName": "p", "InstalledVersion": "1"}
            ]
        }]
    }
    report = parse_trivy_output(data, target="img")
    assert report.vulnerabilities[0].severity == "LOW"


def test_apply_gate_fail_on_critical():
    """Fail-on=critical · HIGH no bloquea."""
    data = _sample_trivy_output(severity="HIGH")
    report = parse_trivy_output(data, target="img")
    report = apply_gate(report, fail_on_severity="critical")
    assert report.passed is True


def test_apply_gate_fail_on_high_blocks_critical():
    data = _sample_trivy_output(severity="CRITICAL")
    report = parse_trivy_output(data, target="img")
    report = apply_gate(report, fail_on_severity="high")
    assert report.passed is False
    assert len(report.violations) == 1


def test_trivy_skip_when_not_available():
    data = {"scanner_available": False, "error": "trivy not found"}
    report = parse_trivy_output(data, target="img")
    report = apply_gate(report, fail_on_severity="critical")
    assert report.passed is True


def test_parse_trivy_handles_no_vulnerabilities():
    """Target clean · Results vacío o sin Vulnerabilities."""
    data = {"Results": [{"Target": "img", "Vulnerabilities": None}]}
    report = parse_trivy_output(data, target="img")
    report = apply_gate(report, fail_on_severity="low")
    assert len(report.vulnerabilities) == 0
    assert report.passed is True


def test_format_json_includes_target_and_scan_type():
    data = _sample_trivy_output()
    report = parse_trivy_output(data, target="nginx:1.21", scan_type="image")
    report = apply_gate(report, fail_on_severity="high")
    parsed = json.loads(format_json(report))
    assert parsed["target"] == "nginx:1.21"
    assert parsed["scan_type"] == "image"
    assert parsed["vulnerabilities"][0]["vuln_id"] == "CVE-2024-1234"
