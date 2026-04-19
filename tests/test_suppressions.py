"""Tests · suppressions (waivers) file-based."""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from aios.core.security_gate import Finding
from aios.core.suppressions import (
    Suppression,
    add_suppression,
    apply_suppressions,
    list_expired,
    load_suppressions,
)


def _f(rule_id: str, file: str, line: int, cwe: str = "CWE-89") -> Finding:
    return Finding(
        cwe=cwe, severity="HIGH", rule_id=rule_id, file=file, line=line,
        snippet="",
    )


def test_load_returns_empty_when_no_file(tmp_path):
    assert load_suppressions(tmp_path) == []


def test_load_parses_suppressions(tmp_path):
    data = [{
        "rule_id": "STATIC-SQL-FSTRING",
        "file": "x.py",
        "line": 42,
        "cwe": "CWE-89",
        "reason": "legacy · pending refactor",
        "approver": "Christian",
        "approved_at": "2026-04-19",
    }]
    (tmp_path / "aios-suppressions.json").write_text(
        json.dumps(data), encoding="utf-8"
    )
    sups = load_suppressions(tmp_path)
    assert len(sups) == 1
    assert sups[0].rule_id == "STATIC-SQL-FSTRING"
    assert sups[0].line == 42


def test_load_handles_malformed_json(tmp_path):
    (tmp_path / "aios-suppressions.json").write_text("{not json")
    assert load_suppressions(tmp_path) == []


def test_load_handles_non_list(tmp_path):
    (tmp_path / "aios-suppressions.json").write_text('{"rule_id":"x"}')
    assert load_suppressions(tmp_path) == []


def test_suppression_matches_exact():
    s = Suppression(rule_id="R-A", file="a.py", line=10)
    assert s.matches(_f("R-A", "a.py", 10))
    assert not s.matches(_f("R-B", "a.py", 10))
    assert not s.matches(_f("R-A", "b.py", 10))
    assert not s.matches(_f("R-A", "a.py", 11))


def test_suppression_line_zero_is_wildcard():
    s = Suppression(rule_id="R-A", file="a.py", line=0)
    assert s.matches(_f("R-A", "a.py", 5))
    assert s.matches(_f("R-A", "a.py", 99))
    assert not s.matches(_f("R-A", "b.py", 5))  # file still strict


def test_is_expired_with_no_expiration():
    s = Suppression(rule_id="x", file="y", line=0)
    assert not s.is_expired()


def test_is_expired_past_date():
    s = Suppression(
        rule_id="x", file="y", line=0,
        expires_at=str(date.today() - timedelta(days=1)),
    )
    assert s.is_expired()


def test_is_expired_future_date():
    s = Suppression(
        rule_id="x", file="y", line=0,
        expires_at=str(date.today() + timedelta(days=30)),
    )
    assert not s.is_expired()


def test_apply_suppressions_excludes_matching():
    findings = [
        _f("R-A", "a.py", 10),
        _f("R-B", "b.py", 5),
        _f("R-A", "a.py", 20),
    ]
    sups = [Suppression(rule_id="R-A", file="a.py", line=10)]
    active, suppressed = apply_suppressions(findings, sups)
    assert len(active) == 2
    assert len(suppressed) == 1
    assert suppressed[0][0].line == 10


def test_apply_suppressions_ignores_expired():
    findings = [_f("R-A", "a.py", 10)]
    sups = [Suppression(
        rule_id="R-A", file="a.py", line=10,
        expires_at=str(date.today() - timedelta(days=1)),
    )]
    active, suppressed = apply_suppressions(findings, sups)
    # Expired waiver NO suprime · finding sigue activo
    assert len(active) == 1
    assert len(suppressed) == 0


def test_add_suppression_creates_file(tmp_path):
    sup = Suppression(
        rule_id="R-X", file="x.py", line=1,
        reason="test", approver="tester", approved_at="2026-04-19",
    )
    dest = add_suppression(tmp_path, sup)
    assert dest.exists()
    data = json.loads(dest.read_text())
    assert len(data) == 1
    assert data[0]["rule_id"] == "R-X"


def test_add_suppression_appends(tmp_path):
    s1 = Suppression(rule_id="R-1", file="a.py", line=1, reason="r1", approver="a")
    s2 = Suppression(rule_id="R-2", file="b.py", line=2, reason="r2", approver="b")
    add_suppression(tmp_path, s1)
    add_suppression(tmp_path, s2)
    data = json.loads((tmp_path / "aios-suppressions.json").read_text())
    assert len(data) == 2


def test_list_expired():
    today = date(2026, 4, 19)
    sups = [
        Suppression(rule_id="R-1", file="x", line=0, expires_at="2026-01-01"),  # expired
        Suppression(rule_id="R-2", file="x", line=0, expires_at="2027-01-01"),  # active
        Suppression(rule_id="R-3", file="x", line=0),  # no expiration
    ]
    expired = list_expired(sups, today=today)
    assert len(expired) == 1
    assert expired[0].rule_id == "R-1"


def test_security_gate_respects_suppressions(tmp_path):
    """End-to-end · run_security_gate con waiver debe suprimir finding."""
    from aios.core.security_gate import run_security_gate

    (tmp_path / "bad.py").write_text('pickle.loads(x)\n')
    # Sin suppression · deberia FAIL
    r1 = run_security_gate(tmp_path)
    assert r1["status"] == "fail"

    # Con suppression matching el finding · debe pass
    sup = Suppression(
        rule_id="STATIC-PICKLE-DESERIALIZATION",
        file="bad.py", line=1,
        reason="legacy · safe upstream",
        approver="test",
    )
    add_suppression(tmp_path, sup)
    r2 = run_security_gate(tmp_path)
    assert r2.get("suppressed_count", 0) >= 1
    assert r2["status"] == "pass"  # 0 CRITICAL restantes
