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


# ─────────────────────────────────────────────────────────────────────
# v3.7.4 · G-RULE-ID-UNIFY · alias `rule` + match por CWE
# ─────────────────────────────────────────────────────────────────────

def test_load_accepts_rule_alias_for_rule_id(tmp_path):
    """v3.7.4 · suppressions externas suelen usar `rule`. Aceptarlo
    como alias de `rule_id` evita que el usuario tenga que duplicar
    entries cuando migra desde otros formatos."""
    data = [{
        "rule": "STATIC-SQL-FSTRING",  # alias
        "file": "x.py",
        "line": 42,
    }]
    (tmp_path / "aios-suppressions.json").write_text(
        json.dumps(data), encoding="utf-8"
    )
    sups = load_suppressions(tmp_path)
    assert len(sups) == 1
    assert sups[0].rule_id == "STATIC-SQL-FSTRING"


def test_load_prefers_rule_id_over_alias_when_both_present(tmp_path):
    """Si la entry trae ambos, el campo canónico gana."""
    data = [{"rule_id": "CANONICAL", "rule": "ALIAS", "file": "x"}]
    (tmp_path / "aios-suppressions.json").write_text(json.dumps(data))
    sups = load_suppressions(tmp_path)
    assert sups[0].rule_id == "CANONICAL"


def test_matches_falls_back_to_cwe_when_rule_id_is_cwe_form():
    """v3.7.4 · suppression con rule_id="CWE-547" debe cubrir cualquier
    detector que emita ese CWE (HARDCODED-INTERNAL-HOSTNAME, etc.).
    Patrón observado en FLEET_OPS_APP donde la misma línea es flagged por
    detectores con rule_id distinto pero comparten CWE."""
    sup = Suppression(rule_id="CWE-547", file="x.cs", line=144)
    finding = _f("HARDCODED-INTERNAL-HOSTNAME", "x.cs", 144, cwe="CWE-547")
    assert sup.matches(finding) is True


def test_matches_cwe_fallback_is_case_insensitive():
    sup = Suppression(rule_id="cwe-547", file="x.cs", line=10)
    finding = _f("HARDCODED-X", "x.cs", 10, cwe="CWE-547")
    assert sup.matches(finding) is True


def test_matches_cwe_fallback_does_not_match_when_cwe_differs():
    sup = Suppression(rule_id="CWE-547", file="x.cs", line=10)
    finding = _f("HARDCODED-X", "x.cs", 10, cwe="CWE-89")
    assert sup.matches(finding) is False


def test_matches_with_only_cwe_set_requires_finding_cwe():
    """rule_id vacío + cwe set → exige match exacto en finding.cwe."""
    sup = Suppression(rule_id="", cwe="CWE-547", file="x.cs", line=10)
    fmatch = _f("ANY-RULE", "x.cs", 10, cwe="CWE-547")
    fmiss = _f("ANY-RULE", "x.cs", 10, cwe="CWE-89")
    assert sup.matches(fmatch) is True
    assert sup.matches(fmiss) is False


def test_load_legacy_entry_with_rule_alias_and_cwe_field(tmp_path):
    """Entry legacy FLEET_OPS_APP-shape: { id, rule (alias), file, line }.
    Carga sin error y matchea findings por rule_id resuelto."""
    data = [{
        "id": "T3-FP-001",
        "rule": "CWE-547",
        "file": "src/x.cs",
        "line": 144,
        "reason": "denylist intencional · T-06 IMDS",
    }]
    (tmp_path / "aios-suppressions.json").write_text(
        json.dumps(data), encoding="utf-8"
    )
    sups = load_suppressions(tmp_path)
    assert len(sups) == 1
    # rule_id = "CWE-547" via alias resolution
    assert sups[0].rule_id == "CWE-547"
    # matchea finding emitido con rule_id distinto pero mismo CWE (gap fix)
    finding = _f("HARDCODED-INTERNAL-HOSTNAME", "src/x.cs", 144, cwe="CWE-547")
    assert sups[0].matches(finding) is True


def test_paths_match_helper_exact():
    """v3.7.5 G-PATH-NORMALIZATION T8-N1 · _paths_match helper · exact match"""
    from aios.core.suppressions import _paths_match
    assert _paths_match("src/x.cs", "src/x.cs") is True
    assert _paths_match("x.py", "x.py") is True


def test_paths_match_helper_scope_reduced():
    """v3.7.5 G-PATH-NORMALIZATION T8-N1 · scope-reduced match.
    Caso real: suppression con repo-root path + finding con --root subdir path."""
    from aios.core.suppressions import _paths_match
    # suppression repo-root, finding scope-reduced
    assert _paths_match(
        "infra/cdk-pipeline/stacks/sicofav_kms_stack.py",
        "stacks/sicofav_kms_stack.py",
    ) is True
    # symmetric: finding repo-root, suppression scope-reduced
    assert _paths_match(
        "stacks/sicofav_kms_stack.py",
        "infra/cdk-pipeline/stacks/sicofav_kms_stack.py",
    ) is True


def test_paths_match_helper_separator_aware():
    """v3.7.5 G-PATH-NORMALIZATION T8-N1 · separator-aware · NO false positives"""
    from aios.core.suppressions import _paths_match
    # NO match · 'admin-x.py' termina con 'x.py' pero sin separator
    assert _paths_match("stacks/admin-x.py", "x.py") is False
    # NO match · paths divergen completamente
    assert _paths_match("other/x.py", "stacks/x.py") is False
    # NO match · prefix-only sin separator
    assert _paths_match("stacks_old/x.py", "stacks/x.py") is False


def test_paths_match_helper_windows_paths():
    """v3.7.5 · normalize backslash → forward slash (Windows path tolerance)"""
    from aios.core.suppressions import _paths_match
    assert _paths_match(
        "infra\\cdk-pipeline\\stacks\\x.py",
        "stacks/x.py",
    ) is True


def test_t8_n1_e2e_suppression_matches_with_scope_reduced_finding():
    """T8-N1 e2e · suppression repo-root path matchea finding emitido con --root subdir."""
    sup = Suppression(
        rule_id="ACME-CDK-STACK-REQUIRES-MANDATORY-TAGS",
        file="infra/cdk-pipeline/stacks/sicofav_kms_stack.py",
        line=31,
    )
    # Finding emitido por `aios iterate --root infra/cdk-pipeline` · path relativo a --root
    finding = _f(
        "ACME-CDK-STACK-REQUIRES-MANDATORY-TAGS",
        "stacks/sicofav_kms_stack.py",
        31,
    )
    assert sup.matches(finding) is True, (
        "T8-N1 fix: suppression con repo-root path debe matchear finding scope-reduced"
    )
