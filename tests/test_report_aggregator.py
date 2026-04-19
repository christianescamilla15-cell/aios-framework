"""Tests · report_aggregator · AIOS aggregate report."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aios.core.report_aggregator import (
    AggregateReport,
    ReportSection,
    build_report,
    write_report,
)


def _init_project(tmp_path: Path):
    (tmp_path / "ai-memory").mkdir()
    (tmp_path / "ai-system").mkdir()
    (tmp_path / "specs").mkdir()
    (tmp_path / "ai-memory" / "product_context.md").write_text("# p")
    (tmp_path / "ai-memory" / "tech_context.md").write_text("# t")
    (tmp_path / "ai-memory" / "active_workstream.md").write_text(
        "# Active\n**Task:** test\n**Mode:** FEATURE\n"
    )


def test_report_section_dataclass():
    s = ReportSection(title="x", body="body", status="pass")
    assert s.title == "x"
    assert s.status == "pass"


def test_aggregate_report_to_markdown_includes_sections(tmp_path):
    report = AggregateReport(
        generated_at="2026-04-19T12:00:00+00:00",
        root=str(tmp_path),
        sections=[
            ReportSection(title="A", body="body A", status="pass"),
            ReportSection(title="B", body="body B", status="warn"),
        ],
    )
    md = report.to_markdown()
    assert "# AIOS Aggregate Report" in md
    assert "## A" in md
    assert "body A" in md
    assert "## B" in md
    assert "body B" in md


def test_build_report_has_4_sections(tmp_path):
    _init_project(tmp_path)
    report = build_report(tmp_path)
    titles = [s.title for s in report.sections]
    assert "Release Gate" in titles
    assert "Last Arena self-play run" in titles
    assert "Arena SARIF findings (recent runs)" in titles
    assert "Nemesis engagements" in titles


def test_build_report_no_arena_run_shows_info(tmp_path):
    _init_project(tmp_path)
    report = build_report(tmp_path)
    arena_sec = next(s for s in report.sections if s.title == "Last Arena self-play run")
    assert "No hay runs registrados" in arena_sec.body


def test_build_report_reads_last_arena_from_memory(tmp_path):
    _init_project(tmp_path)
    # Simula que aios arena corrio antes
    memory = tmp_path / "ai-memory" / "security_findings.md"
    memory.write_text(
        "# Security findings · Arena runs\n\n"
        "## Run 2026-04-19T15:00:00+00:00 · amx-mini-refund\n\n"
        "- **Verdict:** `MYTHOS_WINS` [OK]\n"
        "- **Rounds completed:** 6\n"
    )
    report = build_report(tmp_path)
    arena_sec = next(s for s in report.sections if s.title == "Last Arena self-play run")
    assert "amx-mini-refund" in arena_sec.body
    assert "MYTHOS_WINS" in arena_sec.body
    assert arena_sec.status == "pass"


def test_build_report_picks_up_sarif_file(tmp_path):
    _init_project(tmp_path)
    runs = tmp_path / "arena" / "arena-memory" / "runs" / "arena-test"
    runs.mkdir(parents=True)
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "arena", "rules": [
                {"id": "R1"}, {"id": "R2"}
            ]}},
            "results": [{"ruleId": "R1"}],
            "properties": {
                "arena_run_id": "arena-test",
                "verdict": "MYTHOS_WINS",
                "nemesis_confirmed_exploits": 3,
            },
        }],
    }
    (runs / "findings.sarif").write_text(json.dumps(sarif))
    report = build_report(tmp_path)
    sarif_sec = next(s for s in report.sections
                     if s.title.startswith("Arena SARIF"))
    assert "arena-test" in sarif_sec.body
    assert "MYTHOS_WINS" in sarif_sec.body
    # 1 finding total
    assert "Total findings" in sarif_sec.body


def test_write_report_creates_reports_dir(tmp_path):
    _init_project(tmp_path)
    report = build_report(tmp_path)
    dest = write_report(tmp_path, report)
    assert dest.exists()
    assert dest.name.startswith("aios_report_")
    assert dest.name.endswith(".md")
    assert "# AIOS Aggregate Report" in dest.read_text()


def test_engagements_section_detects_roe_signed_status(tmp_path):
    _init_project(tmp_path)
    eng_dir = tmp_path / "nemesis" / "nemesis-engagements" / "2026-Q2-foo-dry-run"
    eng_dir.mkdir(parents=True)
    (eng_dir / "roe.yaml").write_text(
        "starts_at: 2099-01-01T00:00:00Z\n"
        "approver_signatures_verified: false\n"
    )
    report = build_report(tmp_path)
    eng_sec = next(s for s in report.sections if s.title == "Nemesis engagements")
    assert "2026-Q2-foo-dry-run" in eng_sec.body
    assert "frozen" in eng_sec.body
    assert "NO" in eng_sec.body  # signed = NO
