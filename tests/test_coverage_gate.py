"""v3.6.0 · G-06 Coverage Gate tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aios.core.coverage_gate import (
    CoverageReport,
    PackageCoverage,
    apply_gate,
    find_cobertura_file,
    format_human,
    format_json,
    parse_cobertura,
)


def _write_cobertura(tmp_path: Path, line_rate: float = 0.85,
                     branch_rate: float = 0.82,
                     packages: list[dict] | None = None) -> Path:
    """Escribe un cobertura.xml minimal en tmp_path."""
    pkgs_xml = ""
    for p in (packages or []):
        pkgs_xml += (
            f'<package name="{p["name"]}" line-rate="{p.get("line_rate", 0.85)}" '
            f'branch-rate="{p.get("branch_rate", 0.82)}" '
            f'lines-valid="{p.get("lines_valid", 100)}" '
            f'branches-valid="{p.get("branches_valid", 50)}">'
            f'</package>'
        )

    xml = (
        f'<?xml version="1.0"?>'
        f'<coverage line-rate="{line_rate}" branch-rate="{branch_rate}" '
        f'lines-covered="850" lines-valid="1000" '
        f'branches-covered="410" branches-valid="500">'
        f'<packages>{pkgs_xml}</packages>'
        f'</coverage>'
    )
    path = tmp_path / "coverage.cobertura.xml"
    path.write_text(xml)
    return path


def test_find_cobertura_file_recursive(tmp_path: Path):
    """Busca recursivamente el cobertura.xml."""
    sub = tmp_path / "TestResults" / "guid-xxx"
    sub.mkdir(parents=True)
    (sub / "coverage.cobertura.xml").write_text("<coverage/>")

    found = find_cobertura_file(tmp_path)
    assert found is not None
    assert found.name == "coverage.cobertura.xml"


def test_find_cobertura_returns_none_when_missing(tmp_path: Path):
    assert find_cobertura_file(tmp_path) is None


def test_parse_cobertura_basic(tmp_path: Path):
    path = _write_cobertura(tmp_path, line_rate=0.92, branch_rate=0.91,
                            packages=[{"name": "MyApp.Core"}])
    report = parse_cobertura(path)
    assert report.line_rate == pytest.approx(0.92)
    assert report.branch_rate == pytest.approx(0.91)
    assert len(report.packages) == 1
    assert report.packages[0].name == "MyApp.Core"


def test_parse_cobertura_sox_tagging(tmp_path: Path):
    path = _write_cobertura(tmp_path, packages=[
        {"name": "MyApp.Core"},
        {"name": "MyApp.Domain"},
        {"name": "MyApp.Utils"},
    ])
    report = parse_cobertura(path, sox_pattern=r"Domain|Billing")
    sox_pkgs = [p for p in report.packages if p.is_sox_critical]
    assert len(sox_pkgs) == 1
    assert sox_pkgs[0].name == "MyApp.Domain"


def test_apply_gate_passes_when_above_threshold(tmp_path: Path):
    path = _write_cobertura(tmp_path, line_rate=0.85, branch_rate=0.81)
    report = parse_cobertura(path)
    result = apply_gate(report, min_line=80.0, min_branch=80.0,
                        sox_threshold=100.0)
    assert result.passed is True
    assert result.violations == []


def test_apply_gate_fails_on_low_line(tmp_path: Path):
    path = _write_cobertura(tmp_path, line_rate=0.70, branch_rate=0.85)
    report = parse_cobertura(path)
    result = apply_gate(report, min_line=80.0, min_branch=80.0,
                        sox_threshold=100.0)
    assert result.passed is False
    assert any("line coverage 70" in v for v in result.violations)


def test_apply_gate_fails_on_low_branch(tmp_path: Path):
    path = _write_cobertura(tmp_path, line_rate=0.90, branch_rate=0.65)
    report = parse_cobertura(path)
    result = apply_gate(report, min_line=80.0, min_branch=80.0,
                        sox_threshold=100.0)
    assert result.passed is False
    assert any("branch coverage 65" in v for v in result.violations)


def test_apply_gate_sox_critical_fails_below_threshold(tmp_path: Path):
    path = _write_cobertura(tmp_path, line_rate=0.95, branch_rate=0.95,
                            packages=[
                                {"name": "MyApp.Domain",
                                 "line_rate": 0.80, "branch_rate": 0.85},
                            ])
    report = parse_cobertura(path, sox_pattern=r"Domain")
    result = apply_gate(report, min_line=80.0, min_branch=80.0,
                        sox_threshold=100.0)
    assert result.passed is False
    assert any("SOX-critical" in v and "line" in v for v in result.violations)


def test_apply_gate_sox_critical_passes_when_100(tmp_path: Path):
    path = _write_cobertura(tmp_path, line_rate=0.95, branch_rate=0.95,
                            packages=[
                                {"name": "MyApp.Domain",
                                 "line_rate": 1.0, "branch_rate": 1.0},
                            ])
    report = parse_cobertura(path, sox_pattern=r"Domain")
    result = apply_gate(report, min_line=80.0, min_branch=80.0,
                        sox_threshold=100.0)
    assert result.passed is True


def test_format_human_shows_packages_and_verdict(tmp_path: Path):
    path = _write_cobertura(tmp_path, line_rate=0.82,
                            packages=[{"name": "Pkg1"}])
    report = parse_cobertura(path)
    result = apply_gate(report, 80.0, 80.0, 100.0)
    out = format_human(result, 80.0, 80.0, 100.0)
    assert "Coverage Gate" in out
    assert "Pkg1" in out
    assert "PASSED" in out or "FAILED" in out


def test_format_json_serializes(tmp_path: Path):
    path = _write_cobertura(tmp_path)
    report = parse_cobertura(path)
    result = apply_gate(report, 80.0, 80.0, 100.0)
    data = json.loads(format_json(result))
    assert "passed" in data
    assert "violations" in data
    assert "packages" in data
    assert isinstance(data["packages"], list)
