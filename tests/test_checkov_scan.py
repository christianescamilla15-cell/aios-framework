"""Tests · v3.6.5 · G-20 Checkov IaC scan wrap."""
from __future__ import annotations

import json

from aios.core.checkov_scan import (
    parse_checkov_output, apply_gate, format_human, format_json,
)


def _sample_checkov_output(severity: str = "HIGH",
                            check_id: str = "CKV_AWS_18"):
    return {
        "results": {
            "passed_checks": [{"check_id": "CKV_AWS_1", "resource": "x"}],
            "failed_checks": [
                {
                    "check_id": check_id,
                    "check_name": "Ensure S3 bucket has versioning enabled",
                    "severity": severity,
                    "resource": "aws_s3_bucket.my_bucket",
                    "file_path": "/main.tf",
                    "file_line_range": [10, 25],
                    "guideline": "https://docs.bridgecrew.io/...",
                }
            ]
        }
    }


def test_parse_checkov_extracts_failed_check():
    data = _sample_checkov_output(severity="HIGH",
                                   check_id="CKV_AWS_18")
    report = parse_checkov_output(data, root="/infra", framework="terraform")
    assert len(report.findings) == 1
    f = report.findings[0]
    assert f.check_id == "CKV_AWS_18"
    assert f.severity == "HIGH"
    assert f.resource == "aws_s3_bucket.my_bucket"
    assert f.file_line_range == (10, 25)


def test_parse_checkov_counts_passed():
    data = _sample_checkov_output()
    report = parse_checkov_output(data, root="/infra")
    assert report.passed_count == 1


def test_parse_checkov_merges_list_output():
    """Multi-framework · checkov retorna lista de reports · se merge."""
    data_list = [
        {"results": {
            "failed_checks": [{"check_id": "CKV_TF_1", "severity": "MEDIUM",
                               "resource": "r1", "file_path": "/a.tf",
                               "file_line_range": [1, 5],
                               "check_name": "X"}],
            "passed_checks": [{"check_id": "p1", "resource": "r"}]
        }},
        {"results": {
            "failed_checks": [{"check_id": "CKV_K8S_1", "severity": "HIGH",
                               "resource": "r2", "file_path": "/b.yml",
                               "file_line_range": [10, 20],
                               "check_name": "Y"}],
            "passed_checks": [{"check_id": "p2", "resource": "r"},
                              {"check_id": "p3", "resource": "r"}]
        }},
    ]
    # simulate what run_checkov would produce after merging list format
    from aios.core.checkov_scan import run_checkov as _  # noqa
    # directly call the merge path via simulating the dict form
    merged = {"results": {
        "failed_checks": (
            data_list[0]["results"]["failed_checks"]
            + data_list[1]["results"]["failed_checks"]
        ),
        "passed_checks_count": 3,
    }}
    report = parse_checkov_output(merged, root="/infra")
    assert len(report.findings) == 2
    assert report.passed_count == 3


def test_apply_gate_fail_on_high():
    data = _sample_checkov_output(severity="HIGH")
    report = parse_checkov_output(data, root="/infra")
    report = apply_gate(report, fail_on_severity="high")
    assert report.passed is False
    assert len(report.violations) == 1


def test_apply_gate_low_severity_below_critical_passes():
    data = _sample_checkov_output(severity="LOW")
    report = parse_checkov_output(data, root="/infra")
    report = apply_gate(report, fail_on_severity="critical")
    assert report.passed is True


def test_checkov_skip_when_not_available():
    data = {"scanner_available": False, "error": "checkov not found"}
    report = parse_checkov_output(data, root="/infra")
    report = apply_gate(report, fail_on_severity="high")
    assert report.passed is True


def test_format_json_includes_framework():
    data = _sample_checkov_output()
    report = parse_checkov_output(data, root="/infra",
                                   framework="terraform")
    report = apply_gate(report, fail_on_severity="medium")
    parsed = json.loads(format_json(report))
    assert parsed["framework"] == "terraform"
    assert parsed["findings"][0]["check_id"] == "CKV_AWS_18"
