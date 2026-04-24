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


# ── JavaScript / TypeScript · React + Node ────────────────────────────

def test_detects_js_react_dangerouslyhtml(tmp_path):
    (tmp_path / "Comp.jsx").write_text(
        'return <div dangerouslySetInnerHTML={{ __html: msg }} />;\n'
    )
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-79" and "REACT" in f.rule_id for f in findings)


def test_detects_js_dom_innerhtml(tmp_path):
    (tmp_path / "x.ts").write_text('el.innerHTML = userInput;\n')
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-79" and "INNERHTML" in f.rule_id for f in findings)


def test_detects_js_open_redirect(tmp_path):
    (tmp_path / "x.js").write_text('window.location = redirect;\n')
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-601" for f in findings)


def test_detects_js_node_childprocess(tmp_path):
    (tmp_path / "srv.js").write_text(
        'child_process.execSync("ls " + dir, {});\n'
    )
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-78" and "NODE" in f.rule_id for f in findings)


def test_detects_js_node_fs_req(tmp_path):
    (tmp_path / "srv.ts").write_text(
        'fs.readFileSync(req.body.path);\n'
    )
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-22" and "NODE" in f.rule_id for f in findings)


def test_detects_js_node_sql_concat(tmp_path):
    (tmp_path / "srv.js").write_text(
        'pool.query("SELECT * FROM t WHERE id=" + uid);\n'
    )
    findings = scan_directory(tmp_path)
    assert any(f.cwe == "CWE-89" and "NODE" in f.rule_id for f in findings)


# ── Detector extension filter · evita meta-FPs entre lenguajes ────────

def test_csharp_detector_does_not_fire_in_python(tmp_path):
    """Regression · scanner escaneandose a si mismo no debe disparar.

    Detector C# CWE-502 busca BinaryFormatter · si un archivo Python
    menciona ese literal (ej. pattern string del propio scanner),
    NO debe disparar porque el detector solo aplica a `.cs`.
    """
    (tmp_path / "scanner_patterns.py").write_text(
        "# patterns registry\n"
        "PATTERNS = [\n"
        "    (r'BinaryFormatter\\\\.Deserialize', 'C# BinaryFormatter unsafe'),\n"
        "]\n"
    )
    findings = scan_directory(tmp_path)
    assert not any(
        "CSHARP" in f.rule_id for f in findings
    ), "C# detector should not fire in .py files"


def test_php_detector_does_not_fire_in_python(tmp_path):
    (tmp_path / "doc.py").write_text(
        "# La funcion unserialize de PHP es peligrosa.\n"
        "def note(): return 'use_unserialize_carefully'\n"
    )
    findings = scan_directory(tmp_path)
    assert not any("PHP" in f.rule_id for f in findings)


def test_vendored_repos_dir_is_excluded_by_default(tmp_path):
    """Regression · repos/ (vendored test fixtures) no se escanea."""
    (tmp_path / "repos" / "juice-shop").mkdir(parents=True)
    (tmp_path / "repos" / "juice-shop" / "bad.js").write_text(
        "el.innerHTML = userInput;\n"
    )
    findings = scan_directory(tmp_path)
    assert not any("bad.js" in f.file for f in findings)


def test_sql_fstring_requires_sql_keyword(tmp_path):
    """Regression · STATIC-SQL-FSTRING no dispara sin keyword SQL.

    Motivo: FP historico sobre `self.execute(f"analizar X", app)` donde
    execute es metodo de orquestacion · no SQL.
    """
    (tmp_path / "orch.py").write_text(
        'class O:\n'
        '    def run(self, x): return self.execute(f"analizar {x}", "app")\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(f.rule_id == "STATIC-SQL-FSTRING" for f in findings)


# ── CWE-489 · Active Debug Code (Sprint 5.1 · #1) ────────────────────

def test_detects_flask_debug_in_run(tmp_path):
    (tmp_path / "srv.py").write_text(
        'from flask import Flask\napp = Flask(__name__)\n'
        'app.run(host="0.0.0.0", debug=True)\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.cwe == "CWE-489" and f.rule_id == "DEBUG-CODE-FLASK-ACTIVE"
        and f.severity == "CRITICAL"
        for f in findings
    )


def test_detects_flask_debug_via_config(tmp_path):
    (tmp_path / "srv.py").write_text(
        'from flask import Flask\napp = Flask(__name__)\n'
        'app.config["DEBUG"] = True\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "DEBUG-CODE-FLASK-ACTIVE" for f in findings
    )


def test_detects_django_debug_true(tmp_path):
    (tmp_path / "settings.py").write_text(
        'SECRET_KEY = "x"\nDEBUG = True\nALLOWED_HOSTS = []\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.cwe == "CWE-489" and f.rule_id == "DEBUG-CODE-DJANGO-SETTING"
        and f.severity == "HIGH"
        for f in findings
    )


def test_detects_net_customerrors_off(tmp_path):
    (tmp_path / "web.config").write_text(
        '<?xml version="1.0"?>\n<configuration>\n  <system.web>\n'
        '    <customErrors mode="Off" />\n  </system.web>\n</configuration>\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.cwe == "CWE-489"
        and f.rule_id == "DEBUG-CODE-NET-CUSTOMERRORS-OFF"
        for f in findings
    )


def test_detects_net_compilation_debug(tmp_path):
    (tmp_path / "web.config").write_text(
        '<configuration><system.web>'
        '<compilation debug="true" targetFramework="4.7.2" />'
        '</system.web></configuration>\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "DEBUG-CODE-NET-COMPILATION-DEBUG"
        and f.severity == "MEDIUM"
        for f in findings
    )


def test_django_debug_does_not_fire_on_inline_false(tmp_path):
    """Regression · DEBUG = False no dispara."""
    (tmp_path / "settings.py").write_text('DEBUG = False\n')
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "DEBUG-CODE-DJANGO-SETTING" for f in findings
    )


def test_flask_debug_does_not_fire_on_comment(tmp_path):
    """Regression · mencionar debug=True en comment no dispara."""
    (tmp_path / "x.py").write_text(
        '# Do NOT set debug=True in production\n'
        'app.run(host="0.0.0.0")\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "DEBUG-CODE-FLASK-ACTIVE" for f in findings
    )


def test_net_customerrors_on_does_not_fire(tmp_path):
    """Regression · customErrors mode="On" (secure) no dispara."""
    (tmp_path / "web.config").write_text(
        '<configuration><system.web>'
        '<customErrors mode="On" defaultRedirect="~/Error" />'
        '</system.web></configuration>\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        "DEBUG-CODE-NET" in f.rule_id for f in findings
    )


def test_net_debug_detectors_do_not_fire_in_python(tmp_path):
    """Regression · detectores .NET no disparan en .py aunque el texto
    literal aparezca (protege scanner de auto-match)."""
    (tmp_path / "patterns.py").write_text(
        'PATTERNS = [\n'
        '    r\'<customErrors\\\\s+mode="Off"\',\n'
        '    r\'<compilation\\\\s+debug="true"\',\n'
        ']\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        "DEBUG-CODE-NET" in f.rule_id for f in findings
    )


# ── CWE-532 · Sensitive Data in Logs (Sprint 5.1 · #2) ───────────────

def test_detects_sensitive_log_py_variable(tmp_path):
    (tmp_path / "auth.py").write_text(
        'def login(user, password):\n'
        '    print(password)\n'
        '    logger.info(api_key)\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.cwe == "CWE-532" and f.rule_id == "SENSITIVE-DATA-LOG-PY"
        for f in findings
    )


def test_detects_sensitive_log_py_fstring(tmp_path):
    (tmp_path / "x.py").write_text(
        'logger.info(f"auth token={token}")\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "SENSITIVE-DATA-LOG-PY" for f in findings
    )


def test_detects_sensitive_log_csharp(tmp_path):
    (tmp_path / "Auth.cs").write_text(
        'public class A {\n'
        '    void Log(string password) {\n'
        '        Console.WriteLine(password);\n'
        '        _logger.LogInformation(apiKey);\n'
        '    }\n'
        '}\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "SENSITIVE-DATA-LOG-CSHARP" for f in findings
    )


def test_detects_sensitive_log_java(tmp_path):
    (tmp_path / "Auth.java").write_text(
        'public class Auth {\n'
        '    void log(String password) {\n'
        '        System.out.println(password);\n'
        '        logger.info(apiKey);\n'
        '    }\n'
        '}\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "SENSITIVE-DATA-LOG-JAVA" for f in findings
    )


def test_detects_sensitive_log_php(tmp_path):
    (tmp_path / "auth.php").write_text(
        '<?php\n'
        '$password = $_POST["pwd"];\n'
        'error_log("login " . $password);\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "SENSITIVE-DATA-LOG-PHP" for f in findings
    )


def test_detects_sensitive_log_jsts_console(tmp_path):
    (tmp_path / "auth.ts").write_text(
        'function login(user: string, password: string) {\n'
        '  console.log(password);\n'
        '  console.debug(accessToken);\n'
        '}\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "SENSITIVE-DATA-LOG-JSTS" for f in findings
    )


def test_sensitive_log_py_does_not_fire_on_literal_string(tmp_path):
    """Regression · print("password ok") no dispara · es literal."""
    (tmp_path / "x.py").write_text(
        'def m():\n'
        '    print("Password prompt")\n'
        '    print("token expired")\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id.startswith("SENSITIVE-DATA-LOG-PY") for f in findings
    )


def test_sensitive_log_jsts_does_not_fire_on_literal(tmp_path):
    """Regression · console.log("password invalid") no dispara."""
    (tmp_path / "x.js").write_text(
        'console.log("password invalid");\n'
        'console.error("token expired");\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "SENSITIVE-DATA-LOG-JSTS" for f in findings
    )


def test_sensitive_log_detectors_respect_language_filter(tmp_path):
    """Regression · patterns de sensitive-log no cruzan lang boundary.
    Evitar que detector PHP dispare en .py porque el .py menciona $password."""
    (tmp_path / "note.py").write_text(
        '# Nota: en PHP se escribe $password · no usar en Python\n'
        'PASSWORD_DOC = "see php/auth.php"\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "SENSITIVE-DATA-LOG-PHP" for f in findings
    )


# ── CWE-306 · Missing Auth Critical Function (Sprint 5.1 · #3) ────────

def test_detects_auth_missing_flask_post(tmp_path):
    (tmp_path / "api.py").write_text(
        '@app.post("/refund")\n'
        'def create_refund():\n'
        '    return process_refund()\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.cwe == "CWE-306" and f.rule_id == "AUTH-MISSING-FLASK-ROUTE"
        for f in findings
    )


def test_detects_auth_missing_flask_delete(tmp_path):
    (tmp_path / "api.py").write_text(
        '@app.route("/admin/user/<id>", methods=["DELETE"])\n'
        'def delete_user(id):\n'
        '    return db.users.delete(id)\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "AUTH-MISSING-FLASK-ROUTE" for f in findings
    )


def test_detects_auth_missing_net_controller_post(tmp_path):
    (tmp_path / "Ctrl.cs").write_text(
        'public class RefundController : ControllerBase {\n'
        '    [HttpPost("refund")]\n'
        '    public async Task<IActionResult> CreateRefund() {\n'
        '        return Ok();\n'
        '    }\n'
        '}\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "AUTH-MISSING-NET-CONTROLLER" for f in findings
    )


def test_detects_auth_missing_express_post(tmp_path):
    (tmp_path / "routes.ts").write_text(
        'import express from "express";\n'
        'const router = express.Router();\n'
        'router.post("/transfer", async (req, res) => {\n'
        '    await doTransfer(req.body);\n'
        '});\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "AUTH-MISSING-EXPRESS-ROUTE" for f in findings
    )


def test_auth_missing_flask_no_fire_with_login_required(tmp_path):
    """Regression · ruta POST con @login_required NO dispara."""
    (tmp_path / "api.py").write_text(
        '@app.post("/refund")\n'
        '@login_required\n'
        'def create_refund():\n'
        '    return process_refund()\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "AUTH-MISSING-FLASK-ROUTE" for f in findings
    )


def test_auth_missing_flask_no_fire_with_jwt_required(tmp_path):
    """Regression · FastAPI con @jwt_required NO dispara."""
    (tmp_path / "api.py").write_text(
        '@router.post("/users")\n'
        '@jwt_required()\n'
        'async def create_user():\n'
        '    return {"ok": True}\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "AUTH-MISSING-FLASK-ROUTE" for f in findings
    )


def test_auth_missing_net_no_fire_with_authorize(tmp_path):
    """Regression · [Authorize] presente NO dispara."""
    (tmp_path / "Ctrl.cs").write_text(
        'public class A : ControllerBase {\n'
        '    [HttpPost("refund")]\n'
        '    [Authorize]\n'
        '    public IActionResult Post() { return Ok(); }\n'
        '}\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "AUTH-MISSING-NET-CONTROLLER" for f in findings
    )


def test_auth_missing_express_no_fire_with_middleware(tmp_path):
    """Regression · middleware auth antes del handler NO dispara."""
    (tmp_path / "routes.ts").write_text(
        'router.post("/transfer", authenticate, async (req, res) => {\n'
        '    await doTransfer();\n'
        '});\n'
        'router.delete("/user", requireAuth, (req, res) => res.end());\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "AUTH-MISSING-EXPRESS-ROUTE" for f in findings
    )


def test_auth_missing_flask_get_does_not_fire(tmp_path):
    """Regression · GET route sin auth NO dispara (read-only · scope
    intencional del detector: solo POST/PUT/DELETE/PATCH)."""
    (tmp_path / "api.py").write_text(
        '@app.get("/status")\n'
        'def status():\n'
        '    return {"ok": True}\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "AUTH-MISSING-FLASK-ROUTE" for f in findings
    )


def test_auth_missing_no_fire_with_fastapi_depends_principal(tmp_path):
    """Regression · FastAPI idiom Depends(get_principal) en parametros
    cuenta como auth · no debe disparar."""
    (tmp_path / "api.py").write_text(
        '@app.post("/invoice/process")\n'
        'def process_invoice(\n'
        '    s3_key: str,\n'
        '    xml: bytes,\n'
        '    principal: Principal = Depends(get_principal),\n'
        ') -> dict:\n'
        '    return {"ok": True}\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "AUTH-MISSING-FLASK-ROUTE" for f in findings
    )


def test_auth_missing_no_fire_with_depends_current_user(tmp_path):
    """Regression · Depends(get_current_user) tambien cuenta."""
    (tmp_path / "api.py").write_text(
        '@router.post("/create")\n'
        'async def create(\n'
        '    data: dict,\n'
        '    user: User = Depends(get_current_user),\n'
        '):\n'
        '    return data\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "AUTH-MISSING-FLASK-ROUTE" for f in findings
    )


def test_auth_missing_still_fires_when_depends_is_unrelated(tmp_path):
    """Positive · Depends(get_db) NO es auth · debe disparar."""
    (tmp_path / "api.py").write_text(
        '@app.post("/refund")\n'
        'def refund(\n'
        '    data: dict,\n'
        '    db: Session = Depends(get_db),\n'
        '):\n'
        '    return data\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "AUTH-MISSING-FLASK-ROUTE" for f in findings
    )


# ── CWE-209 · Verbose Error Disclosure (Sprint 5.1 · #4) ──────────────

def test_detects_verbose_error_traceback_py(tmp_path):
    (tmp_path / "api.py").write_text(
        'import traceback\n'
        'def handler():\n'
        '    try: x = 1/0\n'
        '    except Exception: return {"error": traceback.format_exc()}\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.cwe == "CWE-209" and f.rule_id == "VERBOSE-ERROR-TRACEBACK-PY"
        for f in findings
    )


def test_detects_verbose_error_str_e_in_response_py(tmp_path):
    (tmp_path / "api.py").write_text(
        'def handler():\n'
        '    try: x = 1/0\n'
        '    except Exception as e: return {"error": str(e)}\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "VERBOSE-ERROR-EXCEPTION-IN-RESPONSE-PY"
        for f in findings
    )


def test_detects_verbose_error_stack_jsts(tmp_path):
    (tmp_path / "srv.js").write_text(
        'app.get("/err", (req, res) => {\n'
        '  try { doIt(); } catch (err) {\n'
        '    res.json({ trace: err.stack });\n'
        '  }\n'
        '});\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "VERBOSE-ERROR-STACK-JSTS" for f in findings
    )


def test_detects_verbose_error_php_gettraceasstring(tmp_path):
    (tmp_path / "api.php").write_text(
        '<?php\n'
        'try { do_it(); }\n'
        'catch (Exception $e) { echo $e->getTraceAsString(); }\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "VERBOSE-ERROR-DISCLOSURE-PHP" for f in findings
    )


def test_detects_verbose_error_php_display_errors_on(tmp_path):
    (tmp_path / "boot.php").write_text(
        '<?php\n'
        'ini_set("display_errors", "On");\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "VERBOSE-ERROR-DISCLOSURE-PHP" for f in findings
    )


def test_detects_verbose_error_java_printstacktrace(tmp_path):
    (tmp_path / "Ctrl.java").write_text(
        'public class C {\n'
        '    void h(HttpServletResponse response) {\n'
        '        try { doIt(); }\n'
        '        catch (Exception e) {\n'
        '            e.printStackTrace(response.getWriter());\n'
        '        }\n'
        '    }\n'
        '}\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "VERBOSE-ERROR-STACKTRACE-JAVA" for f in findings
    )


def test_detects_verbose_error_csharp_ex_tostring(tmp_path):
    (tmp_path / "Ctrl.cs").write_text(
        'public class C : ControllerBase {\n'
        '    public IActionResult H() {\n'
        '        try { D(); return Ok(); }\n'
        '        catch (Exception ex) { return StatusCode(500, ex.ToString()); }\n'
        '    }\n'
        '}\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "VERBOSE-ERROR-EXCEPTION-CSHARP" for f in findings
    )


def test_verbose_error_py_does_not_fire_on_log_only(tmp_path):
    """Regression · traceback.format_exc() dispara siempre porque es
    poco probable sin intencion de exposicion · pero este test asegura
    que el detector no cruce a otras regex no relacionadas."""
    (tmp_path / "x.py").write_text(
        'def handler():\n'
        '    try: do()\n'
        '    except Exception: logger.exception("failed")\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id.startswith("VERBOSE-ERROR") for f in findings
    )


def test_verbose_error_php_display_errors_off_no_fire(tmp_path):
    """Regression · display_errors=Off (secure) NO dispara."""
    (tmp_path / "boot.php").write_text(
        '<?php\nini_set("display_errors", "Off");\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "VERBOSE-ERROR-DISCLOSURE-PHP" for f in findings
    )


def test_verbose_error_jsts_no_fire_on_message_log(tmp_path):
    """Regression · logger.error(err.stack) NO dispara (es log no
    response · el detector exige res.send/json/write)."""
    (tmp_path / "srv.ts").write_text(
        'function h(err: Error) {\n'
        '  logger.error(err.stack);\n'
        '}\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "VERBOSE-ERROR-STACK-JSTS" for f in findings
    )


# ── CWE-284 · Insecure Bind External (Sprint 5.1 · #5) ────────────────

def test_detects_insecure_bind_flask(tmp_path):
    (tmp_path / "srv.py").write_text(
        'from flask import Flask\napp = Flask(__name__)\n'
        'app.run(host="0.0.0.0", port=8080)\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.cwe == "CWE-284" and f.rule_id == "INSECURE-BIND-PYTHON"
        for f in findings
    )


def test_detects_insecure_bind_uvicorn(tmp_path):
    (tmp_path / "srv.py").write_text(
        'import uvicorn\n'
        'uvicorn.run("main:app", host="0.0.0.0", port=8000)\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "INSECURE-BIND-PYTHON" for f in findings
    )


def test_detects_insecure_bind_socket(tmp_path):
    (tmp_path / "s.py").write_text(
        'import socket\ns = socket.socket()\ns.bind(("0.0.0.0", 5555))\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "INSECURE-BIND-PYTHON" for f in findings
    )


def test_detects_insecure_bind_django_wildcard_host(tmp_path):
    (tmp_path / "settings.py").write_text(
        'SECRET_KEY = "x"\nDEBUG = False\nALLOWED_HOSTS = ["*"]\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "INSECURE-BIND-DJANGO-WILDCARD-HOST" for f in findings
    )


def test_detects_insecure_bind_node_express(tmp_path):
    (tmp_path / "srv.js").write_text(
        'app.listen(8080, "0.0.0.0", () => console.log("up"));\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "INSECURE-BIND-NODE-EXPRESS" for f in findings
    )


def test_insecure_bind_localhost_no_fire(tmp_path):
    """Regression · bind a 127.0.0.1 (secure) NO dispara."""
    (tmp_path / "srv.py").write_text(
        'app.run(host="127.0.0.1", port=8080)\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "INSECURE-BIND-PYTHON" for f in findings
    )


def test_insecure_bind_django_specific_host_no_fire(tmp_path):
    """Regression · ALLOWED_HOSTS con dominio especifico NO dispara."""
    (tmp_path / "settings.py").write_text(
        'ALLOWED_HOSTS = ["app.example.com", "api.example.com"]\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "INSECURE-BIND-DJANGO-WILDCARD-HOST"
        for f in findings
    )


def test_insecure_bind_node_localhost_no_fire(tmp_path):
    """Regression · Node bind a localhost NO dispara."""
    (tmp_path / "srv.js").write_text(
        'app.listen(8080, "127.0.0.1");\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "INSECURE-BIND-NODE-EXPRESS" for f in findings
    )


# ── CWE-547 · Hardcoded Security Constants (Sprint 5.2 · #6) ──────────

def test_detects_hardcoded_internal_hostname_corp(tmp_path):
    (tmp_path / "config.py").write_text(
        'SABRE_HOST = "sabre-gateway.corp.aeromexico.com"\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.cwe == "CWE-547" and f.rule_id == "HARDCODED-INTERNAL-HOSTNAME"
        for f in findings
    )


def test_detects_hardcoded_internal_hostname_local(tmp_path):
    (tmp_path / "config.js").write_text(
        'const DB_HOST = "db-primary.internal.local";\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "HARDCODED-INTERNAL-HOSTNAME" for f in findings
    )


def test_detects_hardcoded_internal_hostname_miatech(tmp_path):
    (tmp_path / "settings.cs").write_text(
        'public const string PRAXIS_HOST = "praxis.miatech.com";\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "HARDCODED-INTERNAL-HOSTNAME" for f in findings
    )


def test_detects_hardcoded_env_url_staging(tmp_path):
    (tmp_path / "config.py").write_text(
        'API_URL = "https://staging-api.example.com/v1/"\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "HARDCODED-ENV-URL-PREFIX" for f in findings
    )


def test_detects_hardcoded_env_url_qa(tmp_path):
    (tmp_path / "settings.java").write_text(
        'public static final String URL = "https://qa-backend.example.com/";\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "HARDCODED-ENV-URL-PREFIX" for f in findings
    )


def test_hardcoded_hostname_public_domain_no_fire(tmp_path):
    """Regression · hostname publico conocido NO dispara."""
    (tmp_path / "c.py").write_text(
        'GOOGLE = "www.google.com"\nGITHUB = "api.github.com"\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "HARDCODED-INTERNAL-HOSTNAME" for f in findings
    )


def test_hardcoded_env_url_prod_domain_no_fire(tmp_path):
    """Regression · URL sin prefix env explicito NO dispara."""
    (tmp_path / "c.py").write_text(
        'URL = "https://api.example.com/v1/"\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "HARDCODED-ENV-URL-PREFIX" for f in findings
    )


def test_hardcoded_hostname_short_var_no_fire(tmp_path):
    """Regression · strings cortos o no-hostname NO disparan.
    Ej: una palabra suelta que accidentalmente contenga '.local'
    como sufijo no debe disparar sin forma hostname."""
    (tmp_path / "c.py").write_text(
        'MSG = "set to local"\nLBL = "local var"\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "HARDCODED-INTERNAL-HOSTNAME" for f in findings
    )


# ── CWE-256/522 · Credentials Plaintext Storage (Sprint 5.2 · #7) ────

def test_detects_credential_webconfig_plaintext(tmp_path):
    (tmp_path / "web.config").write_text(
        '<configuration>\n'
        '  <appSettings>\n'
        '    <add key="DBPassword" value="SuperSecret123!" />\n'
        '    <add key="ApiKey" value="ABC123XYZ" />\n'
        '  </appSettings>\n'
        '</configuration>\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.cwe == "CWE-522"
        and f.rule_id == "CREDENTIAL-PLAINTEXT-WEBCONFIG"
        for f in findings
    )


def test_detects_credential_file_write_py(tmp_path):
    (tmp_path / "dump.py").write_text(
        'def save(pwd):\n'
        '    with open("passwords.txt", "w") as f:\n'
        '        f.write(pwd)\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "CREDENTIAL-PLAINTEXT-FILE-WRITE-PY"
        for f in findings
    )


def test_detects_credential_env_file_write(tmp_path):
    (tmp_path / "bootstrap.py").write_text(
        'def setup():\n'
        '    with open(".env", "w") as f:\n'
        '        f.write("DB_PASSWORD=s3cret\\n")\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "CREDENTIAL-PLAINTEXT-FILE-WRITE-PY"
        for f in findings
    )


def test_detects_credential_connection_string(tmp_path):
    (tmp_path / "config.cs").write_text(
        'public static string Conn = "Server=db.internal;Database=app;'
        'User=admin;Password=MyP@ssw0rd;";\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "CREDENTIAL-PLAINTEXT-CONNECTION-STRING"
        for f in findings
    )


def test_detects_credential_pwd_connection_string(tmp_path):
    (tmp_path / "app.py").write_text(
        'DSN = "Server=10.0.0.1;Database=db;Uid=user;Pwd=rawpass;"\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "CREDENTIAL-PLAINTEXT-CONNECTION-STRING"
        for f in findings
    )


def test_credential_webconfig_placeholder_no_fire(tmp_path):
    """Regression · valor placeholder tipo ${DBPassword} NO dispara."""
    (tmp_path / "web.config").write_text(
        '<configuration><appSettings>'
        '<add key="DBPassword" value="${DB_PASSWORD}" />'
        '<add key="ApiKey" value="$(APIKEY)" />'
        '</appSettings></configuration>\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "CREDENTIAL-PLAINTEXT-WEBCONFIG" for f in findings
    )


def test_credential_conn_string_placeholder_no_fire(tmp_path):
    """Regression · Password={placeholder} NO dispara."""
    (tmp_path / "cfg.cs").write_text(
        'var c = "Server=db;Database=x;User=u;Password={DB_PWD};";\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "CREDENTIAL-PLAINTEXT-CONNECTION-STRING"
        for f in findings
    )


def test_credential_file_write_unrelated_filename_no_fire(tmp_path):
    """Regression · open() sobre archivo no-credential NO dispara."""
    (tmp_path / "x.py").write_text(
        'with open("output.txt", "w") as f: f.write("data")\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "CREDENTIAL-PLAINTEXT-FILE-WRITE-PY"
        for f in findings
    )


# ── CWE-703 · Bare Except Handler (Sprint 5.2 · #8) ──────────────────

def test_detects_bare_except_py(tmp_path):
    (tmp_path / "x.py").write_text(
        'def f():\n'
        '    try: do()\n'
        '    except:\n'
        '        return None\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.cwe == "CWE-703" and f.rule_id == "BARE-EXCEPT-HANDLER-PY"
        for f in findings
    )


def test_detects_except_pass_py(tmp_path):
    (tmp_path / "x.py").write_text(
        'def f():\n'
        '    try: do()\n'
        '    except Exception as e:\n'
        '        pass\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "BARE-EXCEPT-HANDLER-PY" for f in findings
    )


def test_detects_empty_catch_csharp(tmp_path):
    (tmp_path / "X.cs").write_text(
        'public void F() {\n'
        '    try { Do(); }\n'
        '    catch (Exception ex) { }\n'
        '}\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "BARE-EXCEPT-HANDLER-CSHARP" for f in findings
    )


def test_detects_empty_catch_java(tmp_path):
    (tmp_path / "X.java").write_text(
        'public class X {\n'
        '    void f() {\n'
        '        try { do_it(); }\n'
        '        catch (Exception e) { }\n'
        '    }\n'
        '}\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "BARE-EXCEPT-HANDLER-JAVA" for f in findings
    )


def test_detects_empty_catch_jsts(tmp_path):
    (tmp_path / "x.ts").write_text(
        'function f() {\n'
        '  try { doIt(); }\n'
        '  catch (err) { }\n'
        '}\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "BARE-EXCEPT-HANDLER-JSTS" for f in findings
    )


def test_detects_empty_catch_php(tmp_path):
    (tmp_path / "x.php").write_text(
        '<?php\n'
        'try { do_it(); }\n'
        'catch (Exception $e) { }\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "BARE-EXCEPT-HANDLER-PHP" for f in findings
    )


def test_bare_except_no_fire_with_body(tmp_path):
    """Regression · except con body real (no solo pass) NO dispara."""
    (tmp_path / "x.py").write_text(
        'def f():\n'
        '    try: do()\n'
        '    except Exception as e:\n'
        '        logger.exception("failed")\n'
        '        raise\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "BARE-EXCEPT-HANDLER-PY" for f in findings
    )


def test_catch_no_fire_with_body_csharp(tmp_path):
    """Regression · catch con body real NO dispara."""
    (tmp_path / "X.cs").write_text(
        'public void F() {\n'
        '    try { Do(); }\n'
        '    catch (Exception ex) { Log.Error(ex); throw; }\n'
        '}\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "BARE-EXCEPT-HANDLER-CSHARP" for f in findings
    )


def test_catch_no_fire_with_body_jsts(tmp_path):
    """Regression · JS catch con body real NO dispara."""
    (tmp_path / "x.js").write_text(
        'try { doIt(); }\n'
        'catch (err) { console.error(err); throw err; }\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "BARE-EXCEPT-HANDLER-JSTS" for f in findings
    )


# ── CWE-400 · Missing Timeout (Sprint 5.3 · #9) ──────────────────────

def test_detects_missing_timeout_requests_get(tmp_path):
    (tmp_path / "client.py").write_text(
        'import requests\n'
        'r = requests.get("https://api.example.com/")\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.cwe == "CWE-400"
        and f.rule_id == "MISSING-TIMEOUT-REQUESTS-PY"
        for f in findings
    )


def test_detects_missing_timeout_requests_post(tmp_path):
    (tmp_path / "c.py").write_text(
        'import requests\n'
        'requests.post(url, json={"x": 1})\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "MISSING-TIMEOUT-REQUESTS-PY" for f in findings
    )


def test_detects_missing_timeout_urllib(tmp_path):
    (tmp_path / "c.py").write_text(
        'import urllib.request\n'
        'urllib.request.urlopen("https://api.example.com/")\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "MISSING-TIMEOUT-URLLIB-PY" for f in findings
    )


def test_detects_missing_timeout_subprocess_run(tmp_path):
    (tmp_path / "c.py").write_text(
        'import subprocess\n'
        'subprocess.run(["curl", "https://example.com"], capture_output=True)\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "MISSING-TIMEOUT-SUBPROCESS-PY" for f in findings
    )


def test_detects_missing_timeout_fetch_jsts(tmp_path):
    (tmp_path / "c.ts").write_text(
        'async function load() {\n'
        '  const r = await fetch("https://api.example.com/");\n'
        '  return r.json();\n'
        '}\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "MISSING-TIMEOUT-FETCH-JSTS" for f in findings
    )


def test_detects_missing_timeout_axios(tmp_path):
    (tmp_path / "c.js").write_text(
        'const axios = require("axios");\n'
        'const r = await axios.get("https://api.example.com/");\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "MISSING-TIMEOUT-AXIOS-JSTS" for f in findings
    )


def test_missing_timeout_requests_with_timeout_no_fire(tmp_path):
    """Regression · requests.get con timeout= NO dispara."""
    (tmp_path / "c.py").write_text(
        'import requests\n'
        'r = requests.get("https://api.example.com/", timeout=10)\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "MISSING-TIMEOUT-REQUESTS-PY" for f in findings
    )


def test_missing_timeout_subprocess_with_timeout_no_fire(tmp_path):
    """Regression · subprocess.run con timeout= NO dispara."""
    (tmp_path / "c.py").write_text(
        'import subprocess\n'
        'subprocess.run(["ls"], timeout=5, check=True)\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "MISSING-TIMEOUT-SUBPROCESS-PY" for f in findings
    )


def test_missing_timeout_fetch_with_signal_no_fire(tmp_path):
    """Regression · fetch con AbortSignal NO dispara."""
    (tmp_path / "c.ts").write_text(
        'const r = await fetch(url, { signal: AbortSignal.timeout(5000) });\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "MISSING-TIMEOUT-FETCH-JSTS" for f in findings
    )


def test_missing_timeout_axios_with_config_no_fire(tmp_path):
    """Regression · axios con timeout en config NO dispara."""
    (tmp_path / "c.ts").write_text(
        'const r = await axios.get(url, { timeout: 10000 });\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "MISSING-TIMEOUT-AXIOS-JSTS" for f in findings
    )


# ── CWE-770 · Missing Rate Limit (Sprint 5.3 · #10) ──────────────────

def test_detects_missing_rate_limit_flask_post(tmp_path):
    (tmp_path / "api.py").write_text(
        '@app.post("/login")\n'
        '@login_required\n'
        'def login():\n'
        '    return {"ok": True}\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.cwe == "CWE-770"
        and f.rule_id == "MISSING-RATE-LIMIT-FLASK-ROUTE"
        for f in findings
    )


def test_detects_missing_rate_limit_express_post(tmp_path):
    (tmp_path / "routes.ts").write_text(
        'router.post("/login", authenticate, async (req, res) => {\n'
        '    await handleLogin(req.body);\n'
        '});\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "MISSING-RATE-LIMIT-EXPRESS-ROUTE" for f in findings
    )


def test_rate_limit_with_limiter_decorator_no_fire(tmp_path):
    """Regression · @limiter.limit() presente NO dispara."""
    (tmp_path / "api.py").write_text(
        '@app.post("/login")\n'
        '@limiter.limit("5/minute")\n'
        '@login_required\n'
        'def login():\n'
        '    return {"ok": True}\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "MISSING-RATE-LIMIT-FLASK-ROUTE" for f in findings
    )


def test_rate_limit_with_depends_ratelimiter_no_fire(tmp_path):
    """Regression · FastAPI Depends(RateLimiter) NO dispara."""
    (tmp_path / "api.py").write_text(
        '@app.post("/login")\n'
        'async def login(\n'
        '    rl: None = Depends(RateLimiter(times=5, seconds=60)),\n'
        '):\n'
        '    return {"ok": True}\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "MISSING-RATE-LIMIT-FLASK-ROUTE" for f in findings
    )


def test_rate_limit_express_with_limiter_middleware_no_fire(tmp_path):
    """Regression · Express con rateLimit middleware NO dispara."""
    (tmp_path / "routes.ts").write_text(
        'router.post("/login", rateLimit({max: 5}), login);\n'
        'router.post("/register", limiter, register);\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "MISSING-RATE-LIMIT-EXPRESS-ROUTE" for f in findings
    )


def test_sql_fstring_still_fires_with_keyword(tmp_path):
    """Positive · el tightening no rompe detection de SQL real."""
    (tmp_path / "bad.py").write_text(
        'cursor.execute(f"SELECT * FROM users WHERE id={uid}")\n'
    )
    findings = scan_directory(tmp_path)
    assert any(f.rule_id == "STATIC-SQL-FSTRING" for f in findings)


# ═══════════════════════════════════════════════════════════════════
# v3.6.0 · AMX-alignment P0 gaps · tests
# ═══════════════════════════════════════════════════════════════════


def test_amx_dotnet_hardcoded_decrypt_key_sicofav_pattern(tmp_path):
    """G-11 · evidencia real SIC-NEW-01 · SICOFAV Decrypt/cDecrypt.cs:14
    no detectado por v3.5.1 ('Hardcoded credentials (0)' falso negativo).
    """
    (tmp_path / "cDecrypt.cs").write_text(
        'namespace Decrypt\n'
        '{\n'
        '   public class cDecrypt\n'
        '   {\n'
        '      static readonly string password = "M14t3ch@01";\n'
        '      public string Decrypt(string encryptedText) {}\n'
        '   }\n'
        '}\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "AMX-DOTNET-HARDCODED-DECRYPT-KEY" for f in findings
    )


def test_amx_dotnet_hardcoded_decrypt_key_variants(tmp_path):
    """G-11 · variantes naming · masterKey · encryptionKey · apiKey."""
    (tmp_path / "Crypto.cs").write_text(
        'static string masterKey = "AbCdEf123456";\n'
        'static readonly string encryptionKey = "K3yV4lu3";\n'
        'static readonly string apiKey = "sk-live-XXXXXXXX";\n'
    )
    findings = scan_directory(tmp_path)
    amx = [f for f in findings if f.rule_id == "AMX-DOTNET-HARDCODED-DECRYPT-KEY"]
    assert len(amx) >= 3


def test_amx_dotnet_hardcoded_decrypt_key_no_fp_empty_string(tmp_path):
    """G-11 · FP-safe · string vacío o muy corto no debe disparar."""
    (tmp_path / "Clean.cs").write_text(
        'static readonly string password = "";\n'
        'static readonly string pwd = "x";\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "AMX-DOTNET-HARDCODED-DECRYPT-KEY" for f in findings
    )


def test_amx_dotnet_predictable_salt_linear(tmp_path):
    """G-12 · evidencia real SIC-NEW-02 · salt 1..8 en Decrypt/cDecrypt.cs."""
    (tmp_path / "Crypto.cs").write_text(
        'public class Crypto\n'
        '{\n'
        '   private static byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };\n'
        '}\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "AMX-DOTNET-PREDICTABLE-SALT" for f in findings
    )


def test_amx_dotnet_predictable_salt_zeros(tmp_path):
    """G-12 · salt todos ceros · antipatrón común."""
    (tmp_path / "Crypto.cs").write_text(
        'var salt = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "AMX-DOTNET-PREDICTABLE-SALT" for f in findings
    )


def test_amx_dotnet_predictable_salt_no_fp_random_context(tmp_path):
    """G-12 · FP-safe · byte array que NO es salt (ej. cmd buffer) no dispara."""
    (tmp_path / "Buffer.cs").write_text(
        'var commandBuffer = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };\n'
        'var packet = new byte[] { 0xFF, 0x00, 0xAA };\n'
    )
    findings = scan_directory(tmp_path)
    # Solo dispara con nombre de variable salt/saltBytes/saltArray
    assert not any(
        f.rule_id == "AMX-DOTNET-PREDICTABLE-SALT" for f in findings
    )


# ═══════════════════════════════════════════════════════════════════
# v3.6.1 · Sprint 2 · 6 detectores CDK/ServiceCatalog Block 8 infra
# ═══════════════════════════════════════════════════════════════════


def test_amx_cdk_bootstrap_default_forbidden_hits_plain_cdk(tmp_path):
    """G-NEW-2 · `cdk bootstrap` sin --template dispara."""
    (tmp_path / "deploy.sh").write_text(
        "#!/bin/bash\ncdk bootstrap aws://123456789012/us-east-1\n"
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "AMX-CDK-BOOTSTRAP-DEFAULT-FORBIDDEN" for f in findings
    )


def test_amx_cdk_bootstrap_default_no_fp_with_template(tmp_path):
    """G-NEW-2 · `cdk bootstrap --template X` NO dispara."""
    (tmp_path / "deploy.sh").write_text(
        "#!/bin/bash\ncdk bootstrap "
        "--template cdk_bootstraping/bootstrap-template.yml "
        "aws://123456789012/us-east-1\n"
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "AMX-CDK-BOOTSTRAP-DEFAULT-FORBIDDEN" for f in findings
    )


def test_amx_cdk_admin_access_policy_managed_name(tmp_path):
    """G-NEW-2b · AdministratorAccess en CDK code dispara."""
    (tmp_path / "stack.py").write_text(
        'from aws_cdk import aws_iam as iam\n'
        'role.add_managed_policy(\n'
        '    iam.ManagedPolicy.from_aws_managed_policy_name'
        '("AdministratorAccess"))\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "AMX-CDK-ADMIN-ACCESS-POLICY" for f in findings
    )


def test_amx_cdk_admin_access_policy_no_fp_scoped_policy(tmp_path):
    """G-NEW-2b · Policy scoped `AMX-P-DVPS-*` NO dispara."""
    (tmp_path / "stack.py").write_text(
        'role.add_managed_policy(\n'
        '    iam.ManagedPolicy.from_aws_managed_policy_name'
        '("AMX-P-DVPS-CDK-TOOLKIT"))\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "AMX-CDK-ADMIN-ACCESS-POLICY" for f in findings
    )


def test_amx_cdk_fstring_with_token_fires(tmp_path):
    """G-NEW-5 · f-string con CfnParameter.value_as_string dispara."""
    (tmp_path / "stack.py").write_text(
        'bucket_name = f"amx-bucket-{env_param.value_as_string}"\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "AMX-CDK-FSTRING-WITH-TOKEN" for f in findings
    )


def test_amx_cdk_fstring_no_fp_static_string(tmp_path):
    """G-NEW-5 · f-string sin Token NO dispara."""
    (tmp_path / "stack.py").write_text(
        'msg = f"deployed {datetime.now()} OK"\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "AMX-CDK-FSTRING-WITH-TOKEN" for f in findings
    )


def test_amx_cdk_str_concat_token_plus(tmp_path):
    """G-NEW-5b · param.value_as_string + "..." dispara."""
    (tmp_path / "stack.py").write_text(
        'bucket_name = param.value_as_string + "-suffix"\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "AMX-CDK-STR-CONCAT-TOKEN" for f in findings
    )


def test_amx_cdk_str_concat_token_str_call(tmp_path):
    """G-NEW-5b · str(param.value_as_string) dispara."""
    (tmp_path / "stack.py").write_text(
        'x = str(env.value_as_string)\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "AMX-CDK-STR-CONCAT-TOKEN" for f in findings
    )


def test_amx_cdk_str_concat_token_lower_method(tmp_path):
    """G-NEW-5b · param.value_as_string.lower() dispara."""
    (tmp_path / "stack.py").write_text(
        'name = p.value_as_string.lower()\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "AMX-CDK-STR-CONCAT-TOKEN" for f in findings
    )


def test_amx_cdk_str_concat_no_fp_fn_join(tmp_path):
    """G-NEW-5b · Fn.join permitido · NO dispara STR-CONCAT."""
    (tmp_path / "stack.py").write_text(
        'name = Fn.join("-", ["amx", env.value_as_string])\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "AMX-CDK-STR-CONCAT-TOKEN" for f in findings
    )


def test_amx_sc_productstack_missing_validate_false(tmp_path):
    """G-NEW-6 · ProductStack sin validate_template=False dispara."""
    (tmp_path / "product.py").write_text(
        'from aws_cdk import aws_servicecatalog as servicecatalog\n'
        'class MyProduct(servicecatalog.ProductStack):\n'
        '    def __init__(self, scope, id, **kwargs):\n'
        '        super().__init__(scope, id, **kwargs)\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "AMX-SC-PRODUCTSTACK-MISSING-VALIDATE-FALSE"
        for f in findings
    )


def test_amx_sc_productstack_with_validate_false_no_fp(tmp_path):
    """G-NEW-6 · ProductStack con validate_template=False NO dispara."""
    (tmp_path / "product.py").write_text(
        'from aws_cdk import aws_servicecatalog as servicecatalog\n'
        'class MyProduct(servicecatalog.ProductStack):\n'
        '    def __init__(self, scope, id, **kwargs):\n'
        '        super().__init__(scope, id, '
        'validate_template=False, **kwargs)\n'
    )
    findings = scan_directory(tmp_path)
    assert not any(
        f.rule_id == "AMX-SC-PRODUCTSTACK-MISSING-VALIDATE-FALSE"
        for f in findings
    )


def test_amx_sc_construct_with_cfn_parameter_fires(tmp_path):
    """G-NEW-6b · CfnParameter en capa L3 Construct dispara."""
    (tmp_path / "l3.py").write_text(
        'from aws_cdk import Construct, CfnParameter\n'
        'class MyService(Construct):\n'
        '    def __init__(self, scope, id, **kwargs):\n'
        '        super().__init__(scope, id, **kwargs)\n'
        '        p = CfnParameter(self, "Bad", type="String")\n'
    )
    findings = scan_directory(tmp_path)
    assert any(
        f.rule_id == "AMX-SC-CONSTRUCT-WITH-CFN-PARAMETER"
        for f in findings
    )
