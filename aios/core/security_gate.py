"""Security Gate · integra el analisis de patrones de Mythos/Nemesis
como parte de `aios release`.

Diseño:
- Embed lite · AIOS trae un scanner de regex simple (subset del
  StaticCodeSmellsRunner de Mythos) · no requiere instalar Mythos.
- Optional handoff · si el usuario tiene `mythos` CLI en PATH, AIOS
  puede delegar para un scan profundo (flag `use_mythos_cli: true`).
- Graceful · sin config, el gate corre con defaults conservadores y
  warn-only (no bloquea release por CRITICAL hasta que el usuario
  opt-in a strict mode).

Configuracion via aios-config.json (seccion `security_gate`):
{
  "enabled": true,
  "strict": false,
  "max_critical": 0,
  "max_high": 5,
  "forbidden_literals": ["<YOUR_FORBIDDEN_LITERAL_1>", "<YOUR_FORBIDDEN_LITERAL_2>"],
  "use_mythos_cli": false,
  "exclude_dirs": [".git", "node_modules", ".venv"],
  "exclude_exts": [".pyc", ".min.js"]
}
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


DEFAULT_CONFIG = {
    "enabled": True,
    "strict": False,
    "max_critical": 0,
    "max_high": 5,
    "forbidden_literals": [],  # usuario agrega sus propios literales forbidden
    "use_mythos_cli": False,
    "mythos_target_id": "aios-release-gate",
    "mythos_timeout_seconds": 60,
    "exclude_dirs": [".git", ".venv", "venv", "node_modules", "__pycache__",
                     "dist", "build", ".pytest_cache", ".mypy_cache",
                     # Vendored third-party / test-fixture repos
                     "repos", "vendor", "third_party", "third-party",
                     # Java/Gradle/Maven build artifacts
                     "target", ".gradle", ".idea",
                     # Python packaging / eggs
                     ".tox", ".eggs"],
    "exclude_exts": [".pyc", ".pyo", ".so", ".exe", ".dll", ".bin",
                     ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".zip", ".min.js"],
    # Files donde el usuario declara el config del propio gate · no deben
    # escanearse por auto-match de los literales declarados.
    "exclude_files": ["aios-config.json"],
    "max_file_size_bytes": 2 * 1024 * 1024,
}


@dataclass
class Finding:
    cwe: str
    severity: str  # CRITICAL · HIGH · MEDIUM · LOW
    rule_id: str
    file: str
    line: int
    snippet: str


# Extension groups · detectores se filtran por ext para evitar meta-FPs
# (p.ej. scanner C# haciendo match sobre su propia regex definida en Python).
_PY = frozenset({".py"})
_CS = frozenset({".cs"})
_JAVA = frozenset({".java"})
_COBOL = frozenset({".cob", ".cbl", ".cpy"})
_PHP = frozenset({".php", ".phtml", ".php3", ".php4", ".php5"})
_JSTS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})
_NETCFG = frozenset({".config"})  # web.config / app.config de ASP.NET
_ANY: frozenset[str] | None = None  # aplica a cualquier extension

# (cwe, pattern, rule_id, severity, description, file_exts)
# file_exts=None → detector corre sobre todo archivo · usar solo para
# patterns genuinamente language-agnostic (ej. hardcoded IPs en configs).
_DETECTORS: list[tuple[str, re.Pattern, str, str, str, frozenset[str] | None]] = [
    (
        "CWE-89",
        re.compile(
            r"""\.execute\(\s*f['"][^'"]{0,400}?"""
            r"""(?i:\bSELECT\b|\bINSERT\s+INTO\b|\bUPDATE\s+\w+\s+SET\b|"""
            r"""\bDELETE\s+FROM\b|\bFROM\s+\w|\bWHERE\s+\w|\bJOIN\s+\w|"""
            r"""\bMERGE\s+INTO\b)"""
        ),
        "STATIC-SQL-FSTRING",
        "CRITICAL",
        "SQL injection · f-string con SQL keyword en cursor.execute",
        _PY,
    ),
    (
        "CWE-89",
        re.compile(r"""\.execute\(\s*(?:"[^"\n]*"|'[^'\n]*')\s*\+"""),
        "STATIC-SQL-CONCAT",
        "CRITICAL",
        "SQL injection · string concat en cursor.execute",
        _PY,
    ),
    (
        "CWE-78",
        re.compile(r"""subprocess\.[a-z]+\([^)]*shell\s*=\s*True"""),
        "STATIC-CMD-SHELL-TRUE",
        "CRITICAL",
        "Command injection · subprocess con shell=True",
        _PY,
    ),
    (
        "CWE-79",
        re.compile(
            r"""return\s+f['"]<[a-zA-Z]+[^>]*>[^<]*\{"""
            r"""(?!html\.escape|markupsafe|bleach)"""
        ),
        "STATIC-XSS-FSTRING-HTML",
        "HIGH",
        "Reflected XSS · f-string HTML sin escape",
        _PY,
    ),
    (
        "CWE-319",
        re.compile(r"""['"]http://(?:172\.|10\.|192\.168)"""),
        "STATIC-CLEARTEXT-LEGACY-IP",
        "HIGH",
        "Clear-text · HTTP (no HTTPS) a IP legacy interna",
        _ANY,
    ),
    (
        "CWE-287",
        re.compile(r"""if\s+\w+\s+is\s+None\s*:\s*\n\s*return\s+True"""),
        "STATIC-AUTH-BYPASS-NONE",
        "HIGH",
        "Auth bypass · header ausente retorna True",
        _PY,
    ),
    (
        "CWE-22",
        re.compile(
            r"""os\.path\.join\(\s*\w+\s*,\s*(\w+)\s*\)|"""
            r"""open\(\s*f['"][^'"\n]*\{\w+\}[^'"\n]*['"]"""
        ),
        "STATIC-PATH-TRAVERSAL",
        "HIGH",
        "Path traversal · user input en open() sin validacion",
        _PY,
    ),
    (
        "CWE-502",
        re.compile(r"""pickle\.(loads?|load)\("""),
        "STATIC-PICKLE-DESERIALIZATION",
        "CRITICAL",
        "Insecure deserialization · pickle.load(s)",
        _PY,
    ),
    (
        "CWE-611",
        re.compile(r"""resolve_entities\s*=\s*True|load_dtd\s*=\s*True"""),
        "STATIC-XXE-LXML",
        "HIGH",
        "XXE · lxml XMLParser con resolve_entities/load_dtd=True",
        _PY,
    ),
    # ── C# / .NET (paridad con Mythos/Nemesis static runners) ────────
    (
        "CWE-89",
        re.compile(
            r"""new\s+SqlCommand\s*\(\s*["']SELECT\b[^"']*["']\s*\+|"""
            r"""\.CommandText\s*=\s*["'][^"']*["']\s*\+"""
        ),
        "STATIC-SQL-CSHARP-CONCAT",
        "CRITICAL",
        "SQL injection C# · concat en SqlCommand / CommandText",
        _CS,
    ),
    (
        "CWE-78",
        re.compile(r"""UseShellExecute\s*=\s*true""", re.IGNORECASE),
        "STATIC-CMD-CSHARP-SHELL-EXECUTE",
        "CRITICAL",
        "Command injection C# · UseShellExecute=true",
        _CS,
    ),
    (
        "CWE-79",
        re.compile(r"""Response\.Write\s*\(\s*Request\.(?:Params|Query|Form)"""),
        "STATIC-XSS-CSHARP-RESPONSE-WRITE",
        "HIGH",
        "Reflected XSS C# · Response.Write sobre Request.*",
        _CS,
    ),
    (
        "CWE-502",
        re.compile(r"""BinaryFormatter|NetDataContractSerializer"""),
        "STATIC-DESERIALIZATION-CSHARP",
        "CRITICAL",
        "Insecure deserialization C# · BinaryFormatter",
        _CS,
    ),
    (
        "CWE-611",
        re.compile(r"""XmlResolver\s*=\s*new\s+XmlUrlResolver"""),
        "STATIC-XXE-CSHARP-XMLRESOLVER",
        "HIGH",
        "XXE C# · XmlDocument con XmlUrlResolver",
        _CS,
    ),
    (
        "CWE-22",
        re.compile(
            r"""File\.(?:ReadAllText|ReadAllBytes|Open|OpenRead)\s*\(\s*\w+\s*\)|"""
            r"""Path\.Combine\s*\([^)]*Request\."""
        ),
        "STATIC-PATH-TRAVERSAL-CSHARP",
        "HIGH",
        "Path traversal C# · File.Read* o Path.Combine sobre Request.*",
        _CS,
    ),
    # ── Java detectors ───────────────────────────────────────────────
    (
        "CWE-89",
        re.compile(
            r"""\.(?:executeQuery|executeUpdate)\s*\(\s*["'][^"']*["']\s*\+"""
        ),
        "STATIC-SQL-JAVA-CONCAT",
        "CRITICAL",
        "SQL injection Java · Statement.executeQuery con concat",
        _JAVA,
    ),
    (
        "CWE-78",
        re.compile(r"""Runtime\.getRuntime\(\)\.exec\s*\("""),
        "STATIC-CMD-JAVA-RUNTIME-EXEC",
        "CRITICAL",
        "Command injection Java · Runtime.getRuntime().exec()",
        _JAVA,
    ),
    (
        "CWE-79",
        re.compile(
            r"""\.getWriter\(\)\.(?:print|write|println)\s*\([^)]*request\.getParameter"""
        ),
        "STATIC-XSS-JAVA-WRITER",
        "HIGH",
        "Reflected XSS Java · getWriter().print(request.getParameter)",
        _JAVA,
    ),
    (
        "CWE-502",
        re.compile(r"""ObjectInputStream\s*\([^)]*\)\.readObject"""),
        "STATIC-DESERIALIZATION-JAVA-OIS",
        "CRITICAL",
        "Insecure deserialization Java · ObjectInputStream.readObject",
        _JAVA,
    ),
    (
        "CWE-611",
        re.compile(
            r"""DocumentBuilderFactory\.newInstance\(\)"""
            r"""(?![\s\S]{0,300}setFeature[\s\S]{0,80}disallow)"""
        ),
        "STATIC-XXE-JAVA-DBF",
        "HIGH",
        "XXE Java · DocumentBuilderFactory sin setFeature secure",
        _JAVA,
    ),
    # ── COBOL ────────────────────────────────────────────────────────
    (
        "CWE-89",
        re.compile(
            r"""EXEC\s+SQL[^.]*['"][^'"]*['"]\s*\|\|\s*\w+""",
            re.IGNORECASE | re.DOTALL,
        ),
        "STATIC-SQL-COBOL-CONCAT",
        "CRITICAL",
        "SQL injection COBOL · EXEC SQL con concat de host variable",
        _COBOL,
    ),
    # ── PHP · Comisiones Indirectas ─────────────────────────────────
    (
        "CWE-89",
        re.compile(
            r"""(?:mysql_query|mysqli_query|->query)\s*\([^)]*["'][^"']*["']\s*\.\s*\$"""
        ),
        "STATIC-SQL-PHP-CONCAT",
        "CRITICAL",
        "SQL injection PHP · mysql_query/mysqli_query/->query con concat",
        _PHP,
    ),
    (
        "CWE-78",
        re.compile(
            r"""(?:\bexec|\bshell_exec|\bsystem|\bpassthru|\bpopen|\bproc_open)\s*\(\s*\$"""
        ),
        "STATIC-CMD-PHP-EXEC",
        "CRITICAL",
        "Command injection PHP · exec/shell_exec/system con var",
        _PHP,
    ),
    (
        "CWE-79",
        re.compile(
            r"""(?:echo|print)\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\["""
        ),
        "STATIC-XSS-PHP-ECHO-SUPERGLOBAL",
        "HIGH",
        "Reflected XSS PHP · echo/print sobre $_GET/_POST/_REQUEST",
        _PHP,
    ),
    (
        "CWE-502",
        re.compile(r"""\bunserialize\s*\("""),
        "STATIC-DESERIALIZATION-PHP-UNSERIALIZE",
        "CRITICAL",
        "Insecure deserialization PHP · unserialize()",
        _PHP,
    ),
    (
        "CWE-22",
        re.compile(
            r"""(?:file_get_contents|fopen|readfile|include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST)"""
        ),
        "STATIC-PATH-TRAVERSAL-PHP",
        "HIGH",
        "Path traversal PHP · file_get_contents/include sobre $_GET/_POST",
        _PHP,
    ),
    (
        "CWE-611",
        re.compile(r"""LIBXML_NOENT|LIBXML_DTDLOAD"""),
        "STATIC-XXE-PHP-LIBXML-NOENT",
        "HIGH",
        "XXE PHP · simplexml/DOMDocument con LIBXML_NOENT/LIBXML_DTDLOAD",
        _PHP,
    ),
    # ── JavaScript / TypeScript · React frontends + Node ─────────────
    (
        "CWE-79",
        re.compile(r"""dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*\w"""),
        "STATIC-XSS-REACT-DANGEROUSLYHTML",
        "HIGH",
        "React XSS · dangerouslySetInnerHTML con valor dinamico",
        _JSTS,
    ),
    (
        "CWE-79",
        re.compile(r"""\.innerHTML\s*=\s*(?!["'][^"']*["']\s*;)\w"""),
        "STATIC-XSS-DOM-INNERHTML",
        "HIGH",
        "DOM XSS · element.innerHTML = variable",
        _JSTS,
    ),
    (
        "CWE-601",
        re.compile(
            r"""window\.location(?:\.href)?\s*=\s*(?!["']https?://[^"']*["'])\w"""
        ),
        "STATIC-OPEN-REDIRECT-JS",
        "HIGH",
        "Open redirect JS · window.location = variable sin validacion",
        _JSTS,
    ),
    (
        "CWE-78",
        re.compile(
            r"""child_process\.(?:exec|execSync|spawn|spawnSync)\s*\([^)]*\+\s*\w+"""
        ),
        "STATIC-CMD-NODE-CHILDPROCESS",
        "CRITICAL",
        "Command injection Node · child_process con concat",
        _JSTS,
    ),
    (
        "CWE-22",
        re.compile(
            r"""fs\.(?:readFile|readFileSync|createReadStream|unlink)\s*\(\s*req\."""
        ),
        "STATIC-PATH-TRAVERSAL-NODE-FS",
        "HIGH",
        "Path traversal Node · fs.read*/unlink sobre req.*",
        _JSTS,
    ),
    (
        "CWE-89",
        re.compile(
            r"""\.query\s*\(\s*["'][^"']*["']\s*\+|"""
            r"""\.execute\s*\(\s*["'][^"']*["']\s*\+\s*req\."""
        ),
        "STATIC-SQL-NODE-CONCAT",
        "CRITICAL",
        "SQL injection Node · db.query/execute con concat",
        _JSTS,
    ),
    # ── CWE-489 · Active Debug Code (Sprint 5.1 · #1) ────────────────
    # Referencias audit: BSP VULN-01 (Flask debug=True · 9.8 CRITICAL ·
    # Werkzeug RCE), Sicofav V-HI-01 (customErrors mode="Off" · HIGH
    # info disclosure).
    (
        "CWE-489",
        re.compile(
            r"""\.run\(\s*[^)]*\bdebug\s*=\s*True|"""
            r"""app\.config\[\s*['"]DEBUG['"]\s*\]\s*=\s*True|"""
            r"""app\.debug\s*=\s*True"""
        ),
        "DEBUG-CODE-FLASK-ACTIVE",
        "CRITICAL",
        "Active debug · Flask debug=True (Werkzeug RCE via PIN bypass)",
        _PY,
    ),
    (
        "CWE-489",
        re.compile(r"""(?m)^\s*DEBUG\s*=\s*True\b"""),
        "DEBUG-CODE-DJANGO-SETTING",
        "HIGH",
        "Active debug · Django settings DEBUG=True (info disclosure)",
        _PY,
    ),
    (
        "CWE-489",
        re.compile(
            r"""<customErrors\s+[^>]*\bmode\s*=\s*["']Off["']""",
            re.IGNORECASE,
        ),
        "DEBUG-CODE-NET-CUSTOMERRORS-OFF",
        "HIGH",
        "Active debug · ASP.NET customErrors mode=Off (YSOD info disclosure)",
        _NETCFG,
    ),
    (
        "CWE-489",
        re.compile(
            r"""<compilation\s+[^>]*\bdebug\s*=\s*["']true["']""",
            re.IGNORECASE,
        ),
        "DEBUG-CODE-NET-COMPILATION-DEBUG",
        "MEDIUM",
        "Active debug · ASP.NET compilation debug=true (perf + audit concern)",
        _NETCFG,
    ),
    # ── CWE-532 · Sensitive Data in Logs (Sprint 5.1 · #2) ───────────
    # Referencias audit · ARC VULN-07 (print() plaintext · MEDIUM),
    # BSP VULN-10 (sin logging estructurado), Robot V-ME-01
    # (CWE-532 transversal), cfdis V-ME-03.
    # Heuristica · matchea cuando un logger/print recibe una variable
    # cuyo nombre contiene credential/token/secret/password/api_key.
    # Se evita literal strings (como `print("password ok")`) via
    # negative lookahead a quote · se captura f-string interpolation
    # y concat con operador.
    (
        "CWE-532",
        re.compile(
            r"""(?:\bprint|logger\.\w+|logging\.\w+|\blog\.\w+|"""
            r"""sys\.stdout\.write)\s*\(\s*"""
            r"""(?:f["'][^"']*\{\s*\w*|(?!["'])\w*)"""
            r"""(?:password|passwd|pwd|secret|token|api_?key|"""
            r"""credential|private_?key|session_?id|bearer|"""
            r"""access_?token|refresh_?token)"""
        ),
        "SENSITIVE-DATA-LOG-PY",
        "HIGH",
        "Info leak · print/logger con variable/f-string de credencial",
        _PY,
    ),
    (
        "CWE-532",
        re.compile(
            r"""(?:Console\.WriteLine|_?[Ll]ogger\.\w+|Log\.\w+|"""
            r"""Debug\.Write(?:Line)?|Trace\.Write(?:Line)?)\s*\(\s*"""
            r"""(?:\$"[^"]*\{\s*\w*|(?!["'])\w*|\w+\s*\+\s*\w*)"""
            r"""(?:[Pp]assword|[Pp]asswd|[Pp]wd|[Ss]ecret|[Tt]oken|"""
            r"""[Aa]pi[Kk]ey|[Cc]redential|[Pp]rivate[Kk]ey|"""
            r"""[Ss]ession[Ii]d|[Bb]earer|[Aa]ccess[Tt]oken)"""
        ),
        "SENSITIVE-DATA-LOG-CSHARP",
        "HIGH",
        "Info leak C# · logger/Console/Debug con variable de credencial",
        _CS,
    ),
    (
        "CWE-532",
        re.compile(
            r"""(?:System\.out\.print(?:ln)?|System\.err\.print(?:ln)?|"""
            r"""logger\.\w+|LOGGER\.\w+|\blog\.\w+)\s*\(\s*"""
            r"""(?:"[^"]*"\s*\+\s*\w*|(?!["'])\w*)"""
            r"""(?:[Pp]assword|[Pp]asswd|[Pp]wd|[Ss]ecret|[Tt]oken|"""
            r"""[Aa]pi[Kk]ey|[Cc]redential|[Pp]rivate[Kk]ey|"""
            r"""[Ss]ession[Ii]d|[Bb]earer|[Aa]ccess[Tt]oken)"""
        ),
        "SENSITIVE-DATA-LOG-JAVA",
        "HIGH",
        "Info leak Java · System.out/logger con variable de credencial",
        _JAVA,
    ),
    (
        "CWE-532",
        re.compile(
            r"""(?:\becho\b|\bprint\b|error_log|var_dump|print_r|syslog|"""
            r"""file_put_contents)\s*\(?\s*[^)]*"""
            r"""\$\w*"""
            r"""(?:password|passwd|pwd|secret|token|api_?key|"""
            r"""credential|private_?key|session_?id|bearer|"""
            r"""access_?token|refresh_?token)""",
            re.IGNORECASE,
        ),
        "SENSITIVE-DATA-LOG-PHP",
        "HIGH",
        "Info leak PHP · echo/error_log/syslog con $var de credencial",
        _PHP,
    ),
    (
        "CWE-532",
        re.compile(
            r"""console\.(?:log|info|debug|warn|error|trace)\s*\(\s*"""
            r"""(?:`[^`]*\$\{\s*\w*|(?!["'`])\w*)"""
            r"""(?:[Pp]assword|[Pp]asswd|[Pp]wd|[Ss]ecret|[Tt]oken|"""
            r"""[Aa]pi[Kk]ey|[Cc]redential|[Pp]rivate[Kk]ey|"""
            r"""[Ss]ession[Ii]d|[Bb]earer|[Aa]ccess[Tt]oken|"""
            r"""[Rr]efresh[Tt]oken)"""
        ),
        "SENSITIVE-DATA-LOG-JSTS",
        "HIGH",
        "Info leak JS/TS · console.X con variable/template de credencial",
        _JSTS,
    ),
    # ── CWE-306 · Missing Auth for Critical Function (Sprint 5.1 #3) ─
    # Referencias audit · ASR VULN-03 (Endpoint sin auth explicita ·
    # CRITICAL) · SRG CWE-306 OWASP A07 (2 apps afectadas).
    # Estrategia · detectar rutas mutating (POST/PUT/DELETE/PATCH)
    # donde la siguiente linea NO sea un decorator de auth. Usa
    # re.DOTALL implicito via `\n(?!...)` · cubre Flask/FastAPI +
    # ASP.NET controllers + Express routes.
    (
        "CWE-306",
        re.compile(
            r"""@(?:app|router|bp|api)\."""
            r"""(?:route|post|put|delete|patch)\s*\([^)]*\)\s*\n"""
            r"""(?!\s*@(?:login_required|jwt_required|requires_auth|"""
            r"""auth_required|requires_scope|admin_required|"""
            r"""token_required|require_api_key|protected|"""
            r"""authenticated|require_role))"""
            r"""\s*(?:async\s+)?def\s+\w+\s*\("""
            # FastAPI idiom · Depends(get_principal|current_user|...)
            # en los parametros cuenta como auth · no dispara.
            r"""(?![\s\S]{0,800}?Depends\s*\(\s*\w*"""
            r"""(?:principal|current_user|user|auth|security|"""
            r"""verify_token|get_api_key|require_|session))""",
            re.MULTILINE,
        ),
        "AUTH-MISSING-FLASK-ROUTE",
        "HIGH",
        "Missing auth · Flask/FastAPI route mutating sin decorator/Depends auth",
        _PY,
    ),
    (
        "CWE-306",
        re.compile(
            r"""\[Http(?:Post|Put|Delete|Patch)\s*(?:\(|\])[^\]]*\]\s*\n"""
            r"""(?!\s*\[(?:Authorize|ApiKeyRequired|RequireAuthorization|"""
            r"""AuthorizeRoles|CustomAuth))"""
            r"""\s*(?:public|internal|protected)\s+"""
            r"""(?:async\s+)?[A-Za-z_][\w<>,\s]*\s+\w+\s*\(""",
            re.MULTILINE,
        ),
        "AUTH-MISSING-NET-CONTROLLER",
        "HIGH",
        "Missing auth · ASP.NET controller mutating sin [Authorize]",
        _CS,
    ),
    (
        "CWE-306",
        re.compile(
            r"""(?:app|router)\.(?:post|put|delete|patch)\s*\(\s*"""
            r"""['"`][^'"`]+['"`]\s*,\s*"""
            r"""(?!(?:[\w.]*(?:auth|jwt|authenticate|verify|protect|"""
            r"""requireAuth|ensureAuth|checkAuth|isAuthenticated|"""
            r"""passport\.authenticate))\s*[,(])"""
            r"""(?:async\s*)?(?:\(|function)"""
        ),
        "AUTH-MISSING-EXPRESS-ROUTE",
        "HIGH",
        "Missing auth · Express route mutating sin middleware auth",
        _JSTS,
    ),
    # ── CWE-209 · Verbose Error Disclosure (Sprint 5.1 · #4) ─────────
    # Referencias audit · Sicofav V-HI-01 (customErrors mode=Off · ya
    # cubierto por CWE-489) · cfdis V-HI-02 (info sensible en errores).
    # Foco de este detector · stack traces / exception full detail
    # propagados al response/client.
    (
        "CWE-209",
        re.compile(r"""traceback\.format_exc\s*\(\s*\)|"""
                   r"""sys\.exc_info\s*\(\s*\)"""),
        "VERBOSE-ERROR-TRACEBACK-PY",
        "HIGH",
        "Info leak · traceback.format_exc/sys.exc_info expuesto (probable response)",
        _PY,
    ),
    (
        "CWE-209",
        re.compile(
            r"""return\s*\{[^}]*["'](?:error|detail|message|exception)["']"""
            r"""[^}]*:\s*(?:str|repr)\s*\(\s*e\s*\)|"""
            r"""HTTPException\s*\([^)]*detail\s*=\s*(?:str|repr)\s*\(\s*e\s*\)"""
        ),
        "VERBOSE-ERROR-EXCEPTION-IN-RESPONSE-PY",
        "MEDIUM",
        "Info leak · str(e)/repr(e) en response body de handler",
        _PY,
    ),
    (
        "CWE-209",
        re.compile(
            r"""res\.(?:send|json|write|end)\s*\([^)]*"""
            r"""(?:err|error|e|exception|ex)\.(?:stack|toString\s*\(\s*\))"""
        ),
        "VERBOSE-ERROR-STACK-JSTS",
        "HIGH",
        "Info leak JS/TS · res.send/json con err.stack o err.toString",
        _JSTS,
    ),
    (
        "CWE-209",
        re.compile(
            r"""->(?:getTraceAsString|getTrace)\s*\(\s*\)|"""
            r"""ini_set\s*\(\s*['"]display_errors['"]\s*,\s*['"]?(?:1|On|true)"""
        ),
        "VERBOSE-ERROR-DISCLOSURE-PHP",
        "HIGH",
        "Info leak PHP · getTraceAsString/display_errors=On",
        _PHP,
    ),
    (
        "CWE-209",
        re.compile(
            r"""e\.printStackTrace\s*\(\s*(?:response\.|resp\.|writer)|"""
            r"""(?:response|resp)\.getWriter\s*\(\s*\)\.(?:print|println|write)"""
            r"""\s*\([^)]*\be\.(?:toString|getMessage)\s*\(\s*\)"""
        ),
        "VERBOSE-ERROR-STACKTRACE-JAVA",
        "HIGH",
        "Info leak Java · printStackTrace/getMessage sobre response writer",
        _JAVA,
    ),
    (
        "CWE-209",
        re.compile(
            r"""StatusCode\s*\(\s*\d+\s*,\s*ex\.(?:ToString|StackTrace|Message)|"""
            r"""Response\.Write\s*\(\s*ex\.(?:ToString|StackTrace)|"""
            r"""return\s+(?:BadRequest|Ok|Problem|Content)\s*\(\s*ex\.(?:ToString|StackTrace)"""
        ),
        "VERBOSE-ERROR-EXCEPTION-CSHARP",
        "HIGH",
        "Info leak C# · Response/StatusCode con ex.ToString/StackTrace",
        _CS,
    ),
    # ── CWE-284 · Insecure Bind External (Sprint 5.1 · #5) ───────────
    # Referencias audit · BSP VULN-02 (Flask bind 0.0.0.0 · CRITICAL),
    # ASR VULN-02 (Flask bind 0.0.0.0 · CRITICAL).
    # Riesgo · servicio expuesto en toda interface · combinado con
    # debug=True escala a RCE (CWE-489). Standalone es HIGH exposure.
    (
        "CWE-284",
        re.compile(
            r"""(?:\.run|\.listen|\.bind|uvicorn\.run|hypercorn\.run|"""
            r"""make_server|serve)\s*\([^)]*"""
            r"""["']0\.0\.0\.0["']"""
        ),
        "INSECURE-BIND-PYTHON",
        "HIGH",
        "Insecure bind · Flask/FastAPI/uvicorn/socket listen en 0.0.0.0",
        _PY,
    ),
    (
        "CWE-284",
        re.compile(
            r"""ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']\s*\]"""
        ),
        "INSECURE-BIND-DJANGO-WILDCARD-HOST",
        "HIGH",
        "Insecure access · Django ALLOWED_HOSTS = ['*'] acepta cualquier Host",
        _PY,
    ),
    (
        "CWE-284",
        re.compile(
            r"""\.listen\s*\([^)]*["'`]0\.0\.0\.0["'`]"""
        ),
        "INSECURE-BIND-NODE-EXPRESS",
        "HIGH",
        "Insecure bind · Node server.listen(port, '0.0.0.0')",
        _JSTS,
    ),
]


def _load_config(root: Path) -> dict:
    """Merge aios-config.json security_gate section con defaults."""
    merged = DEFAULT_CONFIG.copy()
    cfg_file = root / "aios-config.json"
    if cfg_file.exists():
        try:
            data = json.loads(cfg_file.read_text(encoding="utf-8"))
            user = data.get("security_gate", {})
            if isinstance(user, dict):
                merged.update(user)
        except (json.JSONDecodeError, OSError):
            pass
    return merged


def _walk_files(root: Path, config: dict):
    skip_dirs = set(config.get("exclude_dirs", []))
    skip_exts = set(config.get("exclude_exts", []))
    skip_files = set(config.get("exclude_files", []))
    max_size = int(config.get("max_file_size_bytes", 2 * 1024 * 1024))
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.suffix.lower() in skip_exts:
            continue
        if path.name in skip_files:
            continue
        try:
            if path.stat().st_size > max_size:
                continue
        except OSError:
            continue
        yield path


def scan_directory(root: Path, config: Optional[dict] = None) -> list[Finding]:
    """Scan `root` con detectores embedded + forbidden literals."""
    cfg = config or _load_config(root)
    findings: list[Finding] = []
    forbidden = [lit for lit in cfg.get("forbidden_literals", []) if lit]

    for fp in _walk_files(root, cfg):
        try:
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        rel = str(fp.relative_to(root))
        fp_ext = fp.suffix.lower()

        for cwe, pattern, rule_id, severity, desc, file_exts in _DETECTORS:
            if file_exts is not None and fp_ext not in file_exts:
                continue
            for m in pattern.finditer(content):
                line_no = content.count("\n", 0, m.start()) + 1
                lines = content.splitlines()
                snippet = lines[line_no - 1].strip()[:160] if line_no - 1 < len(lines) else ""
                findings.append(Finding(
                    cwe=cwe, severity=severity, rule_id=rule_id,
                    file=rel, line=line_no, snippet=snippet,
                ))

        for literal in forbidden:
            for m in re.finditer(re.escape(literal), content):
                line_no = content.count("\n", 0, m.start()) + 1
                findings.append(Finding(
                    cwe="CWE-798", severity="CRITICAL",
                    rule_id=f"FORBIDDEN-LITERAL-{literal[:20]}",
                    file=rel, line=line_no, snippet=literal,
                ))

    return findings


def scan_files(
    root: Path,
    files: list[str],
    config: Optional[dict] = None,
) -> list[Finding]:
    """Escanea una lista especifica de archivos (relativos a `root`).

    Util para pre-commit hooks que solo quieren analizar staged files.
    Aplica los mismos detectores + forbidden_literals que scan_directory
    pero sin recorrer el filesystem completo.
    """
    cfg = config or _load_config(root)
    findings: list[Finding] = []
    forbidden = [lit for lit in cfg.get("forbidden_literals", []) if lit]
    skip_exts = set(cfg.get("exclude_exts", []))
    skip_files = set(cfg.get("exclude_files", []))

    for file_rel in files:
        file_rel = file_rel.strip()
        if not file_rel:
            continue
        fp = (root / file_rel).resolve()
        # Safety · no salir del root
        try:
            fp.relative_to(root.resolve())
        except ValueError:
            continue
        if not fp.is_file():
            continue
        if fp.suffix.lower() in skip_exts:
            continue
        if fp.name in skip_files:
            continue
        try:
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        fp_ext = fp.suffix.lower()

        for cwe, pattern, rule_id, severity, desc, file_exts in _DETECTORS:
            if file_exts is not None and fp_ext not in file_exts:
                continue
            for m in pattern.finditer(content):
                line_no = content.count("\n", 0, m.start()) + 1
                lines = content.splitlines()
                snippet = (
                    lines[line_no - 1].strip()[:160]
                    if line_no - 1 < len(lines) else ""
                )
                findings.append(Finding(
                    cwe=cwe, severity=severity, rule_id=rule_id,
                    file=file_rel, line=line_no, snippet=snippet,
                ))

        for literal in forbidden:
            for m in re.finditer(re.escape(literal), content):
                line_no = content.count("\n", 0, m.start()) + 1
                findings.append(Finding(
                    cwe="CWE-798", severity="CRITICAL",
                    rule_id=f"FORBIDDEN-LITERAL-{literal[:20]}",
                    file=file_rel, line=line_no, snippet=literal,
                ))
    return findings


def _run_mythos_cli(root: Path, cfg: dict) -> Optional[list[Finding]]:
    """Opt-in · delega al CLI mythos si el usuario lo tiene instalado.

    Solo se usa cuando `use_mythos_cli: true` en config. Util para
    usuarios que ya operan el framework completo (Mythos + catalogos
    AMX-patterns) y quieren reusar ese scan en `aios release`.
    """
    cli = shutil.which("mythos")
    if cli is None:
        return None
    try:
        result = subprocess.run(
            [cli, "scan", cfg.get("mythos_target_id", "aios-release-gate"),
             "--root", str(root), "--json"],
            capture_output=True, text=True,
            timeout=cfg.get("mythos_timeout_seconds", 60),
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode not in (0, 1, 2, 3):  # mythos usa exit codes para PASS/FAIL
        return None
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    findings: list[Finding] = []
    for f in data.get("findings", []):
        findings.append(Finding(
            cwe=f.get("cwe", "CWE-???"),
            severity=f.get("severity", "MEDIUM").upper(),
            rule_id=f.get("rule_id", "MYTHOS-UNKNOWN"),
            file=f.get("file", "?"),
            line=int(f.get("line", 0)),
            snippet=(f.get("snippet") or "")[:160],
        ))
    return findings


def run_security_gate(root: Path) -> dict:
    """Entry point para release_gate · retorna check dict compatible.

    Return schema:
    {
        "check": "Security static scan",
        "status": "pass|warn|fail|skip",
        "detail": "...",
        "blocking": bool,
        "findings_summary": {"CRITICAL": n, "HIGH": n, ...},
        "top_findings": [{"cwe", "file", "line", "rule_id"}, ...],
    }
    """
    cfg = _load_config(root)
    if not cfg.get("enabled", True):
        return {
            "check": "Security static scan",
            "status": "skip",
            "detail": "security_gate.enabled=false en aios-config.json",
            "blocking": False,
        }

    findings: Optional[list[Finding]] = None
    source = "embedded"
    if cfg.get("use_mythos_cli"):
        findings = _run_mythos_cli(root, cfg)
        if findings is not None:
            source = "mythos-cli"
    if findings is None:
        findings = scan_directory(root, cfg)

    # Apply suppressions (file-based waivers) antes de contar severity.
    suppressed_count = 0
    try:
        from .suppressions import apply_suppressions, load_suppressions
        suppressions = load_suppressions(root)
        if suppressions:
            findings, suppressed = apply_suppressions(findings, suppressions)
            suppressed_count = len(suppressed)
    except Exception:  # noqa: BLE001
        pass

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    crit = by_sev.get("CRITICAL", 0)
    high = by_sev.get("HIGH", 0)
    max_crit = int(cfg.get("max_critical", 0))
    max_high = int(cfg.get("max_high", 5))

    blocking = False
    if crit > max_crit:
        status = "fail"
        blocking = True
        detail = f"{crit} CRITICAL > max_critical={max_crit} ({source})"
    elif high > max_high:
        if cfg.get("strict"):
            status = "fail"
            blocking = True
            detail = f"{high} HIGH > max_high={max_high} · strict mode ({source})"
        else:
            status = "warn"
            detail = f"{high} HIGH > max_high={max_high} · non-strict ({source})"
    elif findings:
        status = "warn" if crit + high > 0 else "pass"
        detail = f"{len(findings)} findings · {crit} CRITICAL · {high} HIGH ({source})"
    else:
        status = "pass"
        detail = f"0 findings ({source})"

    top = []
    for f in sorted(findings, key=lambda x: (x.severity != "CRITICAL", x.severity != "HIGH"))[:5]:
        top.append({
            "cwe": f.cwe, "severity": f.severity, "rule_id": f.rule_id,
            "file": f.file, "line": f.line,
        })

    return {
        "check": "Security static scan",
        "status": status,
        "detail": detail + (
            f" · {suppressed_count} suppressed" if suppressed_count else ""
        ),
        "blocking": blocking,
        "findings_summary": by_sev,
        "top_findings": top,
        "suppressed_count": suppressed_count,
    }
