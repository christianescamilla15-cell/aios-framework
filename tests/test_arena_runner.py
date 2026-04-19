"""Tests · aios.core.arena_runner · invocacion del CLI arena."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from aios.core.arena_runner import (
    ArenaResult,
    _parse_stdout,
    list_targets,
    read_last_arena_run,
    run_arena,
    write_arena_summary_to_memory,
)


def test_missing_binary_returns_not_ok():
    with patch("aios.core.arena_runner.shutil.which", return_value=None):
        result = run_arena(target="amx-mini-refund")
    assert result.ok is False
    assert "arena CLI no encontrado" in result.detail


def test_timeout_is_reported():
    with patch("aios.core.arena_runner.shutil.which", return_value="/usr/bin/arena"), \
         patch("aios.core.arena_runner.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="arena", timeout=1)):
        result = run_arena(target="amx-mini-refund", timeout_seconds=1)
    assert result.ok is False
    assert "timeout" in result.detail.lower()


def test_generic_exception_is_caught():
    with patch("aios.core.arena_runner.shutil.which", return_value="/usr/bin/arena"), \
         patch("aios.core.arena_runner.subprocess.run", side_effect=OSError("boom")):
        result = run_arena(target="x")
    assert result.ok is False
    assert "boom" in result.detail


def test_happy_path_parses_verdict():
    stdout = (
        "Arena run · target=amx-mini-refund · max_rounds=10\n"
        "\n"
        "Verdict: MYTHOS_WINS\n"
        "Rounds completed: 6\n"
        "Mythos win streak: 5\n"
        "Stalemate counter: 0\n"
        "Timeline: \n"
        "/path/to/arena-memory/runs/arena-abc123def/timeline.md\n"
    )
    fake = subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")
    with patch("aios.core.arena_runner.shutil.which", return_value="/usr/bin/arena"), \
         patch("aios.core.arena_runner.subprocess.run", return_value=fake):
        result = run_arena(target="amx-mini-refund", max_rounds=10)
    assert result.ok is True
    assert result.verdict == "MYTHOS_WINS"
    assert result.rounds_completed == 6
    assert result.mythos_win_streak == 5
    assert result.run_id == "arena-abc123def"


def test_command_includes_target_url_flag():
    fake = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    with patch("aios.core.arena_runner.shutil.which", return_value="/usr/bin/arena"), \
         patch("aios.core.arena_runner.subprocess.run", return_value=fake) as run:
        run_arena(target="amx-mini-refund", target_url="http://localhost:8888")
    cmd = run.call_args.args[0]
    assert "--target-url" in cmd
    assert "http://localhost:8888" in cmd


def test_command_no_target_url_without_flag():
    fake = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    with patch("aios.core.arena_runner.shutil.which", return_value="/usr/bin/arena"), \
         patch("aios.core.arena_runner.subprocess.run", return_value=fake) as run:
        run_arena(target="amx-mini-refund")
    cmd = run.call_args.args[0]
    assert "--target-url" not in cmd


def test_parse_stdout_handles_partial_output():
    # Si arena crasheo antes de imprimir todo, parser no debe romper
    partial = "Arena run · target=foo\nVerdict: DRAW\n"
    parsed = _parse_stdout(partial)
    assert parsed["verdict"] == "DRAW"
    assert "rounds_completed" not in parsed


def test_list_targets_returns_empty_when_no_cli():
    with patch("aios.core.arena_runner.shutil.which", return_value=None):
        assert list_targets() == []


def test_list_targets_parses_table_output():
    # Simula output del rich table que imprime arena list-targets
    stdout = (
        "                       Arena · TUTs\n"
        "┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓\n"
        "┃ Target ID           ┃ Path                ┃ Has README ┃\n"
        "┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩\n"
        "│ amx-mini-refund     │ amx-mini-refund     │ ✓          │\n"
        "│ damn-vulnerable-api │ damn-vulnerable-api │ ✓          │\n"
        "└─────────────────────┴─────────────────────┴────────────┘\n"
    )
    fake = subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")
    with patch("aios.core.arena_runner.shutil.which", return_value="/usr/bin/arena"), \
         patch("aios.core.arena_runner.subprocess.run", return_value=fake):
        targets = list_targets()
    assert "amx-mini-refund" in targets
    assert "damn-vulnerable-api" in targets


# ── bidirectional integration · memory persistence ────────────────────

def test_write_summary_creates_file(tmp_path):
    (tmp_path / "ai-memory").mkdir()
    result = ArenaResult(
        ok=True, verdict="MYTHOS_WINS", rounds_completed=6,
        mythos_win_streak=5, timeline_path="/x/timeline.md",
        run_id="arena-abc", elapsed_seconds=15.2,
    )
    written = write_arena_summary_to_memory(tmp_path, result, "amx-mini-refund")
    assert written is not None
    content = written.read_text()
    assert "MYTHOS_WINS" in content
    assert "amx-mini-refund" in content
    assert "6" in content  # rounds
    assert "arena-abc" in content


def test_write_summary_skips_when_no_memory_dir(tmp_path):
    result = ArenaResult(ok=True, verdict="DRAW", rounds_completed=3)
    written = write_arena_summary_to_memory(tmp_path, result, "tut")
    assert written is None


def test_write_summary_appends_subsequent_runs(tmp_path):
    (tmp_path / "ai-memory").mkdir()
    r1 = ArenaResult(ok=True, verdict="MYTHOS_WINS", rounds_completed=6)
    r2 = ArenaResult(ok=True, verdict="DRAW", rounds_completed=10)
    write_arena_summary_to_memory(tmp_path, r1, "amx-mini-refund")
    write_arena_summary_to_memory(tmp_path, r2, "damn-vulnerable-api")
    content = (tmp_path / "ai-memory" / "security_findings.md").read_text()
    assert content.count("## Run ") == 2
    assert "MYTHOS_WINS" in content
    assert "DRAW" in content


def test_read_last_returns_latest(tmp_path):
    (tmp_path / "ai-memory").mkdir()
    r1 = ArenaResult(ok=True, verdict="MYTHOS_WINS", rounds_completed=6)
    r2 = ArenaResult(ok=True, verdict="DRAW", rounds_completed=10)
    write_arena_summary_to_memory(tmp_path, r1, "tut-a")
    write_arena_summary_to_memory(tmp_path, r2, "tut-b")
    last = read_last_arena_run(tmp_path)
    assert last is not None
    assert last["target"] == "tut-b"
    assert last["verdict"] == "DRAW"


def test_read_last_returns_none_when_empty(tmp_path):
    assert read_last_arena_run(tmp_path) is None
    (tmp_path / "ai-memory").mkdir()
    assert read_last_arena_run(tmp_path) is None
