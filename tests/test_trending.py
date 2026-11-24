"""Tests · findings trending · historical aggregation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aios.core.trending import (
    _collect_arena_runs,
    _group_by_date,
    build_trending,
    render_ascii_chart,
    render_trending_markdown,
)


def _make_run(
    base: Path, run_id: str, target: str, verdict: str,
    started: str, sarif_findings: int = 0, critical: int = 0,
):
    run_dir = base / "arena" / "arena-memory" / "runs" / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "metadata.json").write_text(json.dumps({
        "run_id": run_id,
        "target_id": target,
        "verdict": verdict,
        "started_at": started,
        "rounds_completed": 5,
        "mythos_win_streak": 3,
        "stalemate_counter": 0,
    }), encoding="utf-8")
    if sarif_findings > 0:
        results = []
        for i in range(sarif_findings):
            results.append({
                "ruleId": f"R-{i}",
                "level": "error" if i < critical else "warning",
                "properties": {"severity": "CRITICAL" if i < critical else "HIGH"},
            })
        (run_dir / "findings.sarif").write_text(json.dumps({
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "arena", "rules": []}},
                "results": results,
            }],
        }), encoding="utf-8")


def test_collect_empty_root_returns_empty(tmp_path):
    assert _collect_arena_runs(tmp_path) == []


def test_collect_single_run(tmp_path):
    _make_run(tmp_path, "arena-1", "tut-a", "DRAW", "2026-04-19T10:00:00Z")
    points = _collect_arena_runs(tmp_path)
    assert len(points) == 1
    assert points[0].target == "tut-a"
    assert points[0].date_iso == "2026-04-19"
    assert points[0].verdict == "DRAW"


def test_collect_multiple_runs_sorted(tmp_path):
    _make_run(tmp_path, "r1", "tut-a", "DRAW", "2026-04-19T10:00:00Z")
    _make_run(tmp_path, "r2", "tut-b", "MYTHOS_WINS", "2026-04-20T10:00:00Z")
    _make_run(tmp_path, "r3", "tut-a", "DRAW", "2026-04-19T12:00:00Z")
    points = _collect_arena_runs(tmp_path)
    assert len(points) == 3


def test_collect_counts_sarif_findings(tmp_path):
    _make_run(tmp_path, "r", "tut", "DRAW", "2026-04-19T10:00:00Z",
              sarif_findings=5, critical=3)
    points = _collect_arena_runs(tmp_path)
    assert points[0].findings_count == 5
    assert points[0].critical == 3


def test_group_by_date_aggregates():
    from aios.core.trending import DataPoint
    points = [
        DataPoint("2026-04-19", "t1", "DRAW", 3, 1, 1),
        DataPoint("2026-04-19", "t2", "DRAW", 2, 0, 2),
        DataPoint("2026-04-20", "t1", "MYTHOS_WINS", 0, 0, 0),
    ]
    daily = _group_by_date(points)
    assert daily["2026-04-19"]["findings"] == 5
    assert daily["2026-04-19"]["critical"] == 1
    assert daily["2026-04-19"]["runs"] == 2
    assert sorted(daily["2026-04-19"]["targets"]) == ["t1", "t2"]
    assert daily["2026-04-20"]["findings"] == 0


def test_ascii_chart_empty_data():
    out = render_ascii_chart({})
    assert "sin datos" in out


def test_ascii_chart_renders_bars(tmp_path):
    daily = {
        "2026-04-19": {"findings": 10, "critical": 2, "high": 3, "runs": 1, "targets": ["t"]},
        "2026-04-20": {"findings": 5,  "critical": 1, "high": 1, "runs": 1, "targets": ["t"]},
    }
    out = render_ascii_chart(daily, field="findings")
    assert "2026-04-19" in out
    assert "2026-04-20" in out
    assert "█" in out


def test_build_trending_full_pipeline(tmp_path):
    _make_run(tmp_path, "r1", "tut-a", "DRAW", "2026-04-19T10:00:00Z",
              sarif_findings=3, critical=1)
    _make_run(tmp_path, "r2", "tut-b", "MYTHOS_WINS", "2026-04-20T10:00:00Z",
              sarif_findings=0)
    data = build_trending(tmp_path)
    assert data["total_arena_runs"] == 2
    assert data["total_findings"] == 3
    assert "2026-04-19" in data["daily"]
    assert "2026-04-20" in data["daily"]


def test_markdown_contains_sections(tmp_path):
    _make_run(tmp_path, "r1", "tut-a", "DRAW", "2026-04-19T10:00:00Z",
              sarif_findings=3, critical=1)
    data = build_trending(tmp_path)
    md = render_trending_markdown(data)
    assert "# Findings Trending" in md
    assert "## Findings por dia" in md
    assert "## CRITICAL por dia" in md
    assert "tut-a" in md


def test_markdown_empty_history():
    data = build_trending(Path("/tmp/path/que/no/existe/aios-trending"))
    md = render_trending_markdown(data)
    assert "Total Arena runs:** 0" in md
