"""Tests · v3.6.5 · G-18 Semgrep SAST wrap."""
from __future__ import annotations

import json

from aios.core.semgrep_scan import (
    parse_semgrep_output, apply_gate, format_human, format_json,
)


def _sample_semgrep_output(severity: str = "ERROR",
                            check_id: str = "python.lang.security.hardcoded-pwd"):
    """Output sintético estilo semgrep scan --json."""
    return {
        "results": [
            {
                "check_id": check_id,
                "path": "src/config.py",
                "start": {"line": 42, "col": 5},
                "end": {"line": 42, "col": 30},
                "extra": {
                    "severity": severity,
                    "message": "Hardcoded password detected",
                    "metadata": {"cwe": ["CWE-798"]},
                },
            }
        ]
    }


def test_parse_semgrep_extracts_finding():
    """Parser extrae check_id + severity + path correctamente."""
    data = _sample_semgrep_output(severity="ERROR", check_id="foo.bar.rule")
    report = parse_semgrep_output(data, root="/tmp/p")
    assert len(report.findings) == 1
    f = report.findings[0]
    assert f.check_id == "foo.bar.rule"
    assert f.severity == "HIGH"  # ERROR → HIGH
    assert f.path == "src/config.py"
    assert f.start_line == 42
    assert "CWE-798" in f.cwe


def test_parse_semgrep_severity_mapping():
    """Mapping ERROR→HIGH · WARNING→MEDIUM · INFO→LOW."""
    data = {
        "results": [
            {"check_id": "a", "path": "x.py", "start": {"line": 1},
             "extra": {"severity": "ERROR", "message": ""}},
            {"check_id": "b", "path": "x.py", "start": {"line": 2},
             "extra": {"severity": "WARNING", "message": ""}},
            {"check_id": "c", "path": "x.py", "start": {"line": 3},
             "extra": {"severity": "INFO", "message": ""}},
        ]
    }
    report = parse_semgrep_output(data, root="/tmp/p")
    sev = {f.check_id: f.severity for f in report.findings}
    assert sev["a"] == "HIGH"
    assert sev["b"] == "MEDIUM"
    assert sev["c"] == "LOW"


def test_apply_gate_fail_on_medium_blocks_high_and_above():
    """Gate fail-on=medium bloquea MEDIUM+HIGH+CRITICAL."""
    data = {
        "results": [
            {"check_id": "a", "path": "x.py", "start": {"line": 1},
             "extra": {"severity": "ERROR", "message": ""}},
            {"check_id": "b", "path": "x.py", "start": {"line": 2},
             "extra": {"severity": "WARNING", "message": ""}},
            {"check_id": "c", "path": "x.py", "start": {"line": 3},
             "extra": {"severity": "INFO", "message": ""}},
        ]
    }
    report = parse_semgrep_output(data, root="/tmp/p")
    report = apply_gate(report, fail_on_severity="medium")
    assert report.passed is False
    assert len(report.violations) == 2  # HIGH + MEDIUM


def test_semgrep_skip_when_not_available():
    """Scanner no disponible · passed=True skip no bloquea."""
    data = {"scanner_available": False, "error": "semgrep not found"}
    report = parse_semgrep_output(data, root="/tmp/p")
    report = apply_gate(report, fail_on_severity="high")
    assert report.passed is True
    assert report.scanner_available is False


def test_format_json_serializable():
    data = _sample_semgrep_output()
    report = parse_semgrep_output(data, root="/tmp/p")
    report = apply_gate(report, fail_on_severity="medium")
    parsed = json.loads(format_json(report))
    assert parsed["passed"] is False
    assert parsed["findings"][0]["severity"] == "HIGH"


def test_format_human_truncates_to_30_rows():
    """Output human cap en 30 rows para no saturar terminal."""
    data = {
        "results": [
            {"check_id": f"rule-{i}", "path": "x.py",
             "start": {"line": i},
             "extra": {"severity": "WARNING", "message": ""}}
            for i in range(40)
        ]
    }
    report = parse_semgrep_output(data, root="/tmp/p")
    out = format_human(report)
    assert "+10 más" in out  # 40 - 30 cap = 10
