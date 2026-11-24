"""Tests · aios.mcp_server · smoke + tool registration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aios.mcp_server import app


def test_mcp_app_registered():
    assert app.name == "aios"


def test_mcp_exposes_expected_tools():
    tools = app._tool_manager.list_tools()
    names = {t.name for t in tools}
    expected = {
        "security_scan",
        "release_gate_check",
        "arena_list_targets",
        "arena_run",
        "engagement_list",
        "engagement_scaffold",
        "aggregate_report",
        "forbidden_literals_suggest",
    }
    assert expected <= names, f"faltan tools: {expected - names}"


def test_mcp_tools_have_descriptions():
    for tool in app._tool_manager.list_tools():
        assert tool.description, f"{tool.name} sin description"
        assert len(tool.description) > 20, f"{tool.name} description muy corta"


def test_security_scan_invalid_path_returns_error():
    """Validacion basica sin invocar el tool via MCP framework (unit)."""
    from aios.mcp_server import security_scan
    result = security_scan("/path/que/no/existe/nunca/jamas/xyz123")
    assert "error" in result


def test_security_scan_clean_project_returns_zero(tmp_path):
    from aios.mcp_server import security_scan
    (tmp_path / "ok.py").write_text("import json\nprint('hi')\n")
    result = security_scan(str(tmp_path))
    assert result["total_findings"] == 0
    assert result["by_severity"] == {}


def test_security_scan_dirty_project_surfaces_findings(tmp_path):
    from aios.mcp_server import security_scan
    (tmp_path / "bad.py").write_text(
        'import pickle\npickle.loads(x)\ncursor.execute(f"SELECT {x}")\n'
    )
    result = security_scan(str(tmp_path))
    assert result["total_findings"] >= 2
    assert result["by_severity"].get("CRITICAL", 0) >= 2
    assert len(result["top_findings"]) >= 2


def test_arena_list_targets_graceful_without_binary(monkeypatch):
    from aios.mcp_server import arena_list_targets
    from aios.core import arena_runner
    monkeypatch.setattr(arena_runner.shutil, "which", lambda x: None)
    result = arena_list_targets()
    assert result["count"] == 0


def test_arena_run_missing_binary_returns_not_ok(monkeypatch):
    from aios.mcp_server import arena_run
    from aios.core import arena_runner
    monkeypatch.setattr(arena_runner.shutil, "which", lambda x: None)
    result = arena_run(target="demo-mini-shop", max_rounds=1)
    assert result["ok"] is False
    assert "no encontrado" in result["detail"]


def test_aggregate_report_returns_markdown(tmp_path):
    from aios.mcp_server import aggregate_report
    (tmp_path / "ai-memory").mkdir()
    (tmp_path / "ai-memory" / "active_workstream.md").write_text(
        "# Active\n**Task:** t\n"
    )
    result = aggregate_report(str(tmp_path))
    assert "markdown" in result
    assert "# AIOS Aggregate Report" in result["markdown"]
    assert result["sections_count"] >= 4


def test_aggregate_report_invalid_path():
    from aios.mcp_server import aggregate_report
    result = aggregate_report("/path/que/no/existe/xyz")
    assert "error" in result


def test_forbidden_literals_suggest_does_not_leak(tmp_path):
    """Regression guard · el tool cuenta los literales del config pero nunca los expone."""
    from aios.mcp_server import forbidden_literals_suggest
    literals = ["DEMO-L1TERAL-0001", "Fict1cio_Pa55w0rd", "legacy-acct-9999"]
    (tmp_path / "aios-config.json").write_text(json.dumps({
        "security_gate": {"enabled": True, "forbidden_literals": literals},
    }))
    result = forbidden_literals_suggest(str(tmp_path))
    assert result["current_forbidden_literals_count"] == 3
    text = json.dumps(result)
    for forbidden in literals:
        assert forbidden not in text, f"LEAK: {forbidden} expuesto en MCP tool"
