"""Tests · security_gate · scanner embedded + integracion release gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aios.core.security_gate import (
    DEFAULT_CONFIG,
    _load_config,
    run_security_gate,
    scan_directory,
)


# ── embedded scanner ──────────────────────────────────────────────────

def test_clean_project_produces_zero_findings(tmp_path):
    (tmp_path / "main.py").write_text(
        'import json\n'
        'def load(payload): return json.loads(payload)\n'
    )
    findings = scan_directory(tmp_path)
    assert findings == []


def test_detects_sql_fstring(tmp_path):
    (tmp_path / "x.py").write_text(
        'cursor.execute(f"SELECT * FROM t WHERE id = {x}")\n'
    )
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-89" for f in findings)


def test_detects_shell_true(tmp_path):
    (tmp_path / "x.py").write_text(
        'import subprocess\nsubprocess.run("ls", shell=True)\n'
    )
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-78" for f in findings)


def test_detects_pickle_loads(tmp_path):
    (tmp_path / "x.py").write_text('import pickle\npickle.loads(b"")\n')
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-502" for f in findings)


def test_detects_xxe_resolve_entities(tmp_path):
    (tmp_path / "x.py").write_text(
        'from lxml import etree\nparser = etree.XMLParser(resolve_entities=True)\n'
    )
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-611" for f in findings)


def test_detects_forbidden_literal(tmp_path):
    # Sample literal · no real · solo fixture de test
    sample = "SAMPLE_SECRET_ABC123"
    (tmp_path / "config.py").write_text(f'PASSWORD = "{sample}"\n')
    cfg = DEFAULT_CONFIG.copy()
    cfg["forbidden_literals"] = [sample]
    findings = scan_directory(tmp_path, cfg)
    assert any("FORBIDDEN-LITERAL" in f.rule_id for f in findings)


def test_skips_excluded_dirs(tmp_path):
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "bad.py").write_text(
        'subprocess.run("x", shell=True)\n'
    )
    findings = scan_directory(tmp_path)
    assert not any("bad.py" in f.file for f in findings)


def test_skips_large_files(tmp_path):
    big = tmp_path / "big.py"
    big.write_text("x = 1\n" * 500_000)  # ~3 MB
    cfg = DEFAULT_CONFIG.copy()
    cfg["max_file_size_bytes"] = 1024  # 1 KB cap
    findings = scan_directory(tmp_path, cfg)
    assert findings == []


# ── config loading ────────────────────────────────────────────────────

def test_config_loads_defaults_without_file(tmp_path):
    cfg = _load_config(tmp_path)
    assert cfg["enabled"] is True
    assert cfg["strict"] is False
    assert cfg["max_critical"] == 0


def test_config_merges_user_overrides(tmp_path):
    (tmp_path / "aios-config.json").write_text(json.dumps({
        "security_gate": {
            "strict": True,
            "max_high": 0,
            "forbidden_literals": ["CUSTOM_LITERAL"],
        }
    }))
    cfg = _load_config(tmp_path)
    assert cfg["strict"] is True
    assert cfg["max_high"] == 0
    assert cfg["forbidden_literals"] == ["CUSTOM_LITERAL"]
    # Defaults preservados
    assert cfg["max_critical"] == 0


def test_config_handles_malformed_json(tmp_path):
    (tmp_path / "aios-config.json").write_text("{not json")
    cfg = _load_config(tmp_path)
    assert cfg == DEFAULT_CONFIG


# ── run_security_gate · integration-ready entry point ────────────────

def test_gate_pass_on_clean_project(tmp_path):
    (tmp_path / "ok.py").write_text("import json\nprint('hi')\n")
    result = run_security_gate(tmp_path)
    assert result["status"] == "pass"
    assert result["blocking"] is False


def test_gate_fails_on_critical_over_threshold(tmp_path):
    (tmp_path / "bad.py").write_text(
        'import pickle\npickle.loads(x)\n'
        'cursor.execute(f"SELECT {x}")\n'
    )
    result = run_security_gate(tmp_path)
    assert result["status"] == "fail"
    assert result["blocking"] is True
    assert result["findings_summary"].get("CRITICAL", 0) >= 2


def test_gate_warn_on_high_non_strict(tmp_path):
    # XSS es HIGH · max_high default 5 · un HIGH debe ser pass
    (tmp_path / "r.py").write_text(
        'def v(u): return f"<h1>{u}</h1>"\n'
    )
    result = run_security_gate(tmp_path)
    assert result["status"] == "warn"
    assert result["blocking"] is False


def test_gate_strict_mode_fails_on_high(tmp_path):
    (tmp_path / "aios-config.json").write_text(json.dumps({
        "security_gate": {"strict": True, "max_high": 0}
    }))
    (tmp_path / "r.py").write_text(
        'def v(u): return f"<h1>{u}</h1>"\n'
    )
    result = run_security_gate(tmp_path)
    assert result["status"] == "fail"
    assert result["blocking"] is True


def test_gate_disabled_returns_skip(tmp_path):
    (tmp_path / "aios-config.json").write_text(json.dumps({
        "security_gate": {"enabled": False}
    }))
    (tmp_path / "bad.py").write_text('pickle.loads(x)\n')
    result = run_security_gate(tmp_path)
    assert result["status"] == "skip"
    assert result["blocking"] is False


def test_gate_returns_top_findings_sorted_by_severity(tmp_path):
    # 1 CRITICAL + 1 HIGH · CRITICAL debe aparecer primero
    (tmp_path / "a.py").write_text('pickle.loads(x)\n')
    (tmp_path / "b.py").write_text('def v(u): return f"<h1>{u}</h1>"\n')
    result = run_security_gate(tmp_path)
    top = result["top_findings"]
    assert len(top) >= 2
    assert top[0]["severity"] == "CRITICAL"


# ── C# / .NET detectors (paridad con Mythos/Nemesis) ──────────────────

def test_detects_csharp_sql_commandtext_concat(tmp_path):
    (tmp_path / "x.cs").write_text(
        'cmd.CommandText = "SELECT * FROM t WHERE id=" + userId;\n'
    )
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-89" and "CSHARP" in f.rule_id for f in findings)


def test_detects_csharp_use_shell_execute(tmp_path):
    (tmp_path / "x.cs").write_text(
        'new ProcessStartInfo { UseShellExecute = true };\n'
    )
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-78" and "CSHARP" in f.rule_id for f in findings)


def test_detects_csharp_response_write_xss(tmp_path):
    (tmp_path / "x.cs").write_text('Response.Write(Request.Params["m"]);\n')
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-79" and "CSHARP" in f.rule_id for f in findings)


def test_detects_csharp_binaryformatter(tmp_path):
    (tmp_path / "x.cs").write_text('new BinaryFormatter();\n')
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-502" and "CSHARP" in f.rule_id for f in findings)


def test_detects_csharp_xmlurlresolver(tmp_path):
    (tmp_path / "x.cs").write_text('doc.XmlResolver = new XmlUrlResolver();\n')
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-611" and "CSHARP" in f.rule_id for f in findings)


def test_detects_csharp_path_combine_request(tmp_path):
    (tmp_path / "x.cs").write_text(
        'var p = Path.Combine("/x/", Request.Params["f"]);\n'
    )
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-22" and "CSHARP" in f.rule_id for f in findings)


def test_release_gate_blocks_on_csharp_critical(tmp_path):
    (tmp_path / "bad.cs").write_text(
        'var bf = new BinaryFormatter(); bf.Deserialize(s);\n'
    )
    result = run_security_gate(tmp_path)
    assert result["status"] == "fail"
    assert result["blocking"] is True
    # CWE-502 CRITICAL
    assert result["findings_summary"].get("CRITICAL", 0) >= 1


# ── PHP detectors · cierra 10/10 scope AMX ────────────────────────────

def test_detects_php_sql_mysqli(tmp_path):
    (tmp_path / "x.php").write_text(
        '<?php mysqli_query($c, "SELECT * WHERE x=" . $_GET["x"]); ?>\n'
    )
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-89" and "PHP" in f.rule_id for f in findings)


def test_detects_php_cmd_system(tmp_path):
    (tmp_path / "x.php").write_text('<?php system($cmd); ?>\n')
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-78" and "PHP" in f.rule_id for f in findings)


def test_detects_php_xss_echo_superglobal(tmp_path):
    (tmp_path / "x.php").write_text('<?php echo $_POST["msg"]; ?>\n')
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-79" and "PHP" in f.rule_id for f in findings)


def test_detects_php_deser_unserialize(tmp_path):
    (tmp_path / "x.php").write_text('<?php $o = unserialize($data); ?>\n')
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-502" and "PHP" in f.rule_id for f in findings)


def test_detects_php_path_traversal_include(tmp_path):
    (tmp_path / "x.php").write_text('<?php include($_GET["p"]); ?>\n')
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-22" and "PHP" in f.rule_id for f in findings)


def test_detects_php_xxe_libxml_noent(tmp_path):
    (tmp_path / "x.php").write_text(
        '<?php simplexml_load_string($x, null, LIBXML_NOENT); ?>\n'
    )
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-611" and "PHP" in f.rule_id for f in findings)
