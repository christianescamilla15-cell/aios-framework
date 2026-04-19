"""Tests · aios.core.engagement_scaffold · wrapper del scaffold.py de Nemesis."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

import pytest

from aios.core.engagement_scaffold import (
    _load_config,
    _resolve_scaffold,
    run_scaffold,
)


def test_config_loads_empty_without_file(tmp_path):
    assert _load_config(tmp_path) == {}


def test_config_parses_engagement_section(tmp_path):
    (tmp_path / "aios-config.json").write_text(json.dumps({
        "engagement": {
            "scaffold_script": "/opt/scaffold.py",
            "quarter_default": "2026-Q3",
        }
    }))
    cfg = _load_config(tmp_path)
    assert cfg["scaffold_script"] == "/opt/scaffold.py"
    assert cfg["quarter_default"] == "2026-Q3"


def test_resolve_uses_config_path_when_present(tmp_path):
    script = tmp_path / "scaffold.py"
    script.write_text("# stub")
    (tmp_path / "aios-config.json").write_text(json.dumps({
        "engagement": {"scaffold_script": str(script)}
    }))
    resolved = _resolve_scaffold(tmp_path)
    assert resolved == script


def test_resolve_returns_none_when_missing(tmp_path):
    with patch("aios.core.engagement_scaffold.COMMON_LOCATIONS", []):
        assert _resolve_scaffold(tmp_path) is None


def test_resolve_falls_back_to_common_location(tmp_path):
    nested = tmp_path / "nemesis" / "nemesis-engagements" / "_catalog"
    nested.mkdir(parents=True)
    script = nested / "scaffold.py"
    script.write_text("# stub")
    resolved = _resolve_scaffold(tmp_path)
    assert resolved is not None
    assert resolved.name == "scaffold.py"


def test_run_scaffold_returns_error_when_missing(tmp_path):
    with patch("aios.core.engagement_scaffold.COMMON_LOCATIONS", []):
        result = run_scaffold(tmp_path, ["--list"])
    assert result.ok is False
    assert "no encontrado" in result.stderr


def test_run_scaffold_invokes_subprocess_with_args(tmp_path):
    script = tmp_path / "scaffold.py"
    script.write_text("# stub")
    (tmp_path / "aios-config.json").write_text(json.dumps({
        "engagement": {"scaffold_script": str(script)}
    }))
    fake = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="OK\n", stderr="",
    )
    with patch("aios.core.engagement_scaffold.subprocess.run",
               return_value=fake) as run:
        result = run_scaffold(tmp_path, ["--app", "02-arc"])
    assert result.ok is True
    assert "OK" in result.stdout
    cmd = run.call_args.args[0]
    assert str(script) in cmd
    assert "--app" in cmd
    assert "02-arc" in cmd


def test_run_scaffold_timeout_is_caught(tmp_path):
    script = tmp_path / "scaffold.py"
    script.write_text("# stub")
    (tmp_path / "aios-config.json").write_text(json.dumps({
        "engagement": {"scaffold_script": str(script)}
    }))
    with patch("aios.core.engagement_scaffold.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="scaffold", timeout=1)):
        result = run_scaffold(tmp_path, ["--list"], timeout=1)
    assert result.ok is False
    assert "timeout" in result.stderr.lower()


def test_run_scaffold_nonzero_exit_reported(tmp_path):
    script = tmp_path / "scaffold.py"
    script.write_text("# stub")
    (tmp_path / "aios-config.json").write_text(json.dumps({
        "engagement": {"scaffold_script": str(script)}
    }))
    fake = subprocess.CompletedProcess(
        args=[], returncode=2, stdout="", stderr="invalid app",
    )
    with patch("aios.core.engagement_scaffold.subprocess.run",
               return_value=fake):
        result = run_scaffold(tmp_path, ["--app", "bogus"])
    assert result.ok is False
    assert result.exit_code == 2
    assert "invalid app" in result.stderr
