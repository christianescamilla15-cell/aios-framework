"""Tests · scan_files · staged file scanner para pre-commit."""

from __future__ import annotations

from pathlib import Path

import pytest

from aios.core.security_gate import DEFAULT_CONFIG, scan_files


def test_scan_files_empty_list(tmp_path):
    assert scan_files(tmp_path, []) == []


def test_scan_files_nonexistent_skipped(tmp_path):
    findings = scan_files(tmp_path, ["does/not/exist.py"])
    assert findings == []


def test_scan_files_only_given_files(tmp_path):
    # Crea 2 files vulnerables · solo escaneamos 1
    (tmp_path / "a.py").write_text('pickle.loads(x)\n')
    (tmp_path / "b.py").write_text('pickle.loads(x)\n')
    findings = scan_files(tmp_path, ["a.py"])
    assert len(findings) == 1
    assert findings[0].file == "a.py"


def test_scan_files_detects_critical(tmp_path):
    (tmp_path / "bad.py").write_text(
        'cursor.execute(f"SELECT * FROM t WHERE id = {x}")\n'
        'pickle.loads(payload)\n'
    )
    findings = scan_files(tmp_path, ["bad.py"])
    crit = [f for f in findings if f.severity == "CRITICAL"]
    assert len(crit) >= 2


def test_scan_files_skips_excluded_exts(tmp_path):
    (tmp_path / "big.pyc").write_text('pickle.loads(x)\n')
    findings = scan_files(tmp_path, ["big.pyc"])
    assert findings == []


def test_scan_files_rejects_path_traversal(tmp_path):
    """Guard · archivo fuera del root no se escanea · no escape."""
    other = tmp_path.parent / "other_outside"
    other.mkdir(exist_ok=True)
    (other / "leak.py").write_text('pickle.loads(x)\n')
    # Intento de escape con ../
    findings = scan_files(tmp_path, ["../other_outside/leak.py"])
    assert findings == []
    # Limpia
    (other / "leak.py").unlink()
    other.rmdir()


def test_scan_files_forbidden_literals(tmp_path):
    (tmp_path / "conf.py").write_text('TOKEN = "CUSTOM_SAMPLE_SECRET"\n')
    cfg = DEFAULT_CONFIG.copy()
    cfg["forbidden_literals"] = ["CUSTOM_SAMPLE_SECRET"]
    findings = scan_files(tmp_path, ["conf.py"], cfg)
    assert any("FORBIDDEN-LITERAL" in f.rule_id for f in findings)


def test_scan_files_multi_lang(tmp_path):
    (tmp_path / "x.py").write_text('pickle.loads(x)\n')
    (tmp_path / "y.cs").write_text('new BinaryFormatter();\n')
    (tmp_path / "z.php").write_text('<?php echo $_GET["m"]; ?>\n')
    findings = scan_files(tmp_path, ["x.py", "y.cs", "z.php"])
    cwes = {f.cwe for f in findings}
    assert "CWE-502" in cwes  # Python + C#
    assert "CWE-79" in cwes   # PHP
