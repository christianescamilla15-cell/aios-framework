"""Tests · iterative_scanner suppressions integration (v3.7.4).

Cierra G-SUPPRESSIONS-ITERATE: hasta v3.7.3 el subcommand `aios iterate`
NO consumía `aios-suppressions.json`, mientras que `aios release` sí lo
hacía vía security_gate. Esto causaba que FPs documentadas reaparecieran
en cada run del scanner iterative.
"""
from __future__ import annotations

import json
from pathlib import Path

from aios.core.iterative_scanner import IterativeScanner


def _suppress(tmp_path: Path, entries: list[dict]) -> None:
    (tmp_path / "aios-suppressions.json").write_text(
        json.dumps(entries), encoding="utf-8",
    )


def test_iterate_applies_suppressions_when_present(tmp_path):
    """v3.7.4 · finding regex-detectable cubierto por suppression debe
    desaparecer del report.all_findings."""
    (tmp_path / "bad.py").write_text('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
    _suppress(tmp_path, [{
        "rule_id": "STATIC-SQL-FSTRING",
        "file": "bad.py",
        "line": 1,
        "reason": "test fixture",
        "approver": "test",
    }])
    report = IterativeScanner(tmp_path, ["regex"], max_iterations=1).run()
    assert report.suppressed_count >= 1
    rules = [f.rule_id for f in report.all_findings]
    assert "STATIC-SQL-FSTRING" not in rules


def test_iterate_no_suppression_file_preserves_legacy_behavior(tmp_path):
    """Sin archivo de suppressions el report no debe cambiar."""
    (tmp_path / "bad.py").write_text('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
    report = IterativeScanner(tmp_path, ["regex"], max_iterations=1).run()
    assert report.suppressed_count == 0
    assert any(f.rule_id == "STATIC-SQL-FSTRING" for f in report.all_findings)


def test_iterate_suppression_via_rule_alias(tmp_path):
    """v3.7.4 · entry con `rule` (alias de rule_id) también filtra."""
    (tmp_path / "bad.py").write_text('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
    _suppress(tmp_path, [{
        "rule": "STATIC-SQL-FSTRING",  # alias en lugar de rule_id
        "file": "bad.py",
        "line": 1,
    }])
    report = IterativeScanner(tmp_path, ["regex"], max_iterations=1).run()
    assert report.suppressed_count >= 1


def test_iterate_suppression_via_cwe_when_rule_id_differs(tmp_path):
    """v3.7.4 · entry con rule_id="CWE-89" cubre findings con ese CWE
    aunque el rule_id concreto sea distinto. Patrón observado en SICOFAV
    (suppression por CWE-547 cubre HARDCODED-INTERNAL-HOSTNAME)."""
    (tmp_path / "bad.py").write_text('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
    _suppress(tmp_path, [{
        "rule_id": "CWE-89",  # CWE en lugar del rule_id concreto
        "file": "bad.py",
        "line": 1,
    }])
    report = IterativeScanner(tmp_path, ["regex"], max_iterations=1).run()
    assert report.suppressed_count >= 1
    assert not any(f.rule_id == "STATIC-SQL-FSTRING" for f in report.all_findings)


def test_iterate_stop_reason_mentions_suppressed_count(tmp_path):
    """v3.7.4 · stop_reason debe documentar suppressions aplicadas para
    auditabilidad post-scan."""
    (tmp_path / "bad.py").write_text('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
    _suppress(tmp_path, [{
        "rule_id": "STATIC-SQL-FSTRING",
        "file": "bad.py",
        "line": 1,
    }])
    report = IterativeScanner(tmp_path, ["regex"], max_iterations=1).run()
    assert "suppressed" in report.stop_reason.lower()


def test_iterate_expired_suppression_does_not_filter(tmp_path):
    """Suppression con expires_at en el pasado NO debe ocultar el finding."""
    (tmp_path / "bad.py").write_text('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
    _suppress(tmp_path, [{
        "rule_id": "STATIC-SQL-FSTRING",
        "file": "bad.py",
        "line": 1,
        "expires_at": "2020-01-01",
    }])
    report = IterativeScanner(tmp_path, ["regex"], max_iterations=1).run()
    assert report.suppressed_count == 0
    assert any(f.rule_id == "STATIC-SQL-FSTRING" for f in report.all_findings)
