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
from dataclasses import dataclass, field
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
                     ".tox", ".eggs",
                     # v3.1 fix · Visual Studio IDE metadata (copilot-chat
                     # sessions matcheaban como credenciales plaintext · 3-4 FPs
                     # consistentes en NoShow)
                     ".vs", ".vscode", "bin", "obj",
                     # v3.3.0 fix · NuGet/vendored libs generan FPs de IP
                     # literal en docs XML (log4net remoteAddress multicast)
                     "packages",
                     # v3.5.0 · SABRE SOAP auto-generated proxies
                     # (Reference.vb/.cs de 1-3 MB cada uno en las apps
                     # VB.NET de Revenue Accounting · ruido sin accionable)
                     "Service References"],
    "exclude_exts": [".pyc", ".pyo", ".so", ".exe", ".dll", ".bin",
                     ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".zip", ".min.js",
                     # Docs · markdown y rst no son codigo · evitar FPs
                     # sobre fixtures citados en docs de audit.
                     ".md", ".rst", ".txt"],
    # Files donde el usuario declara el config del propio gate · no deben
    # escanearse por auto-match de los literales declarados (ej. el
    # archivo de suppressions cita hostnames/literales en el campo
    # reason y file · se matchean a si mismos).
    # v1.7.2 · soporta glob patterns (fnmatch): ej. "tools/**", "*.generated.*"
    "exclude_files": ["aios-config.json", "aios-suppressions.json"],
    # v1.7.2 · default true · filtra findings que caen en lineas de
    # comentario para reducir falsos positivos en comentarios de
    # trazabilidad tipo "// Eliminado: <literal>" que el refactor deja
    # como evidencia del fix aplicado. Setear false para auditoria
    # estricta cuando se quiera detectar TODO incluyendo comentarios.
    "exclude_comment_lines": True,
    "max_file_size_bytes": 2 * 1024 * 1024,
}


# v1.7.2 · patrones de comentario por extension de archivo
# usado por _is_comment_line() para descartar findings en comentarios
# de trazabilidad (reduce FPs de scanner POST-refactor).
_COMMENT_PREFIXES: dict[str, tuple[str, ...]] = {
    # Python · Shell · YAML
    ".py": ("#",), ".sh": ("#",), ".yaml": ("#",), ".yml": ("#",),
    ".toml": ("#",), ".ini": (";", "#"), ".cfg": (";", "#"),
    # C-family · //, /*, * (continuation)
    ".cs": ("//", "/*", "*"), ".java": ("//", "/*", "*"),
    ".js": ("//", "/*", "*"), ".jsx": ("//", "/*", "*"),
    ".ts": ("//", "/*", "*"), ".tsx": ("//", "/*", "*"),
    ".mjs": ("//", "/*", "*"), ".cjs": ("//", "/*", "*"),
    ".c": ("//", "/*", "*"), ".h": ("//", "/*", "*"),
    ".cpp": ("//", "/*", "*"), ".hpp": ("//", "/*", "*"),
    # PHP · mezcla # y // y /*
    ".php": ("//", "#", "/*", "*"),
    ".phtml": ("//", "#", "/*", "*"),
    # Ruby
    ".rb": ("#",),
    # XML · HTML · comentario multiline
    ".xml": ("<!--",), ".html": ("<!--",), ".htm": ("<!--",),
    ".config": ("<!--",),  # ASP.NET web.config / app.config
    # SQL
    ".sql": ("--",),
}


def _is_comment_line(line: str, ext: str) -> bool:
    """v1.7.2 · return True si la linea es comentario (por extension).

    COBOL es caso especial: column 7 con '*' = comentario, o prefijo '*>'.
    Multi-line comments (/* */, <!-- -->): solo detecta la linea de apertura
    y continuacion con '*' · no hace parsing real · suficiente para FPs
    de trazabilidad que son single-line en 99% de los casos.
    """
    stripped = line.lstrip()
    if not stripped:
        return False
    # COBOL · column 7 con '*' o prefijo '*>' (free-format)
    if ext in (".cbl", ".cob", ".cpy"):
        if stripped.startswith("*>"):
            return True
        if len(line) >= 7 and line[6] == "*":
            return True
        return False
    prefixes = _COMMENT_PREFIXES.get(ext, ())
    return any(stripped.startswith(p) for p in prefixes)


def _strip_inline_comments(content: str, ext: str) -> str:
    """v1.7.3 · reemplaza contenido de comentarios con espacios preservando
    offsets + newlines. Evita que regex multi-linea capturen patterns que
    viven DENTRO de un comentario (ej. subprocess.run(... # NO shell=True)).

    Cubre dos casos:
    1. Linea full-comment (ej. '# TODO ...') · reemplaza la linea entera
       con espacios (detectado por _is_comment_line).
    2. Inline comment al final de linea de codigo (ej. 'x = 1  # nota')
       · reemplaza desde el marker hasta el newline con espacios.

    Preserva la estructura exacta del content original para que los
    line_no y match spans sigan siendo correctos.

    Limitacion conocida: no parsea strings · '#' dentro de '"foo # bar"'
    puede falsear como comentario si hay espacio antes. Aceptado como
    trade-off · para auditoria estricta set exclude_comment_lines: false.
    """
    # v1.7.3 · markers inline por extension
    # (no incluimos XML/HTML · <!-- --> multiline requiere parseo real)
    inline_markers = {
        # Python · Shell · YAML · TOML
        ".py": ("#",), ".sh": ("#",), ".yaml": ("#",), ".yml": ("#",),
        ".toml": ("#",), ".rb": ("#",),
        # C-family · inline '//'
        ".cs": ("//",), ".java": ("//",),
        ".js": ("//",), ".jsx": ("//",),
        ".ts": ("//",), ".tsx": ("//",),
        ".mjs": ("//",), ".cjs": ("//",),
        ".c": ("//",), ".h": ("//",),
        ".cpp": ("//",), ".hpp": ("//",),
        # PHP mezcla
        ".php": ("//", "#"), ".phtml": ("//", "#"),
        # SQL
        ".sql": ("--",),
    }
    markers = inline_markers.get(ext, ())
    lines = content.splitlines(keepends=True)
    out: list[str] = []
    for line in lines:
        if _is_comment_line(line, ext):
            # Linea full-comment · blank entire line (preserve newline)
            if line.endswith("\n"):
                out.append(" " * (len(line) - 1) + "\n")
            else:
                out.append(" " * len(line))
            continue
        # Inline comment stripping
        if markers:
            modified = line
            for marker in markers:
                # Busca '\s+<marker>' para no hit dentro de strings puras
                # (approximacion razonable · evita '#' pegado a literal).
                import re as _re
                pat = _re.compile(
                    r"(?<=\s)" + _re.escape(marker) + r"[^\n]*"
                )
                matches = list(pat.finditer(modified))
                if matches:
                    # Blank each inline comment span (keep positions)
                    for m in reversed(matches):
                        blanked = " " * (m.end() - m.start())
                        modified = modified[:m.start()] + blanked + modified[m.end():]
            out.append(modified)
        else:
            out.append(line)
    return "".join(out)


@dataclass
class Finding:
    cwe: str
    severity: str  # CRITICAL · HIGH · MEDIUM · LOW
    rule_id: str
    file: str
    line: int
    snippet: str
    # v1.8.0 · RFC-003 Nivel 1 · ontology classification
    ontology_action: str = "auto_fix"  # auto_fix|pause_for_review|skip|warn
    ontology_match: Optional[str] = None
    ontology_classification: str = "unclear"
    ontology_message: str = ""
    # v1.9.0 · RFC-003 Nivel 2 · LLM classifier output (solo si invocado)
    llm_classification: Optional[str] = None  # bug|business_rule|migration_candidate|unclear
    llm_confidence: float = 0.0  # 0.0-1.0
    llm_reasoning: str = ""
    llm_evidence: list = field(default_factory=list)
    llm_provider: Optional[str] = None
    llm_cached: bool = False


# Extension groups · detectores se filtran por ext para evitar meta-FPs
# (p.ej. scanner C# haciendo match sobre su propia regex definida en Python).
_PY = frozenset({".py"})
_CS = frozenset({".cs"})
_JAVA = frozenset({".java"})
_COBOL = frozenset({".cob", ".cbl", ".cpy"})
_PHP = frozenset({".php", ".phtml", ".php3", ".php4", ".php5"})
_JSTS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})
_NETCFG = frozenset({".config"})  # web.config / app.config de ASP.NET
# v3.5.0 · extension groups añadidos para refinamientos AMX
_VB = frozenset({".vb"})
_PROJ = frozenset({".csproj", ".vbproj"})
_APPSETTINGS = frozenset({".json"})  # filtrado adicional por regex
_ANY: frozenset[str] | None = None  # aplica a cualquier extension

# v3.5.0 · patterns de logging presentes dentro de un bloque catch
# Usado por _catch_block_has_logging() para degradar
# STATIC-GENERIC-EXCEPTION-CATCH-CSHARP de MEDIUM a LOW cuando el
# catch sí registra la exception (el riesgo real es tragarla en silencio).
_CATCH_LOG_PATTERNS: re.Pattern = re.compile(
    r"\b(?:_?[lL]ogger|[lL]og|ILog|_log|ILogger|Serilog|Console|Trace|"
    r"[lL]og4[Nn]et|NLog)\."
    r"(?:Log|LogError|LogWarning|LogInformation|LogCritical|LogDebug|"
    r"LogTrace|Error|Warn|Warning|Info|Information|Fatal|Debug|Trace|"
    r"WriteLine)\s*\(",
)


def _catch_block_has_logging(content: str, catch_match_end: int,
                              max_span: int = 2000) -> bool:
    """v3.5.0 · True si el bloque { ... } que sigue al catch contiene una
    llamada a logger (Serilog / log4net / ILogger / NLog / Console).

    Reduce FPs de `catch (Exception)` que sí loggea · el riesgo real del
    CWE-755 es el handler silencioso que oculta fallas en producción.
    """
    tail = content[catch_match_end:catch_match_end + max_span]
    brace_start = tail.find("{")
    if brace_start < 0:
        return False
    depth = 0
    body_start = -1
    body_end = -1
    for i in range(brace_start, len(tail)):
        ch = tail[i]
        if ch == "{":
            if depth == 0:
                body_start = i + 1
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                body_end = i
                break
    if body_start < 0 or body_end < 0:
        return False
    block = tail[body_start:body_end]
    return bool(_CATCH_LOG_PATTERNS.search(block))


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
    # ── CWE-547 · Hardcoded Security-Relevant Constants (5.2 · #6) ───
    # Referencias audit · ARC VULN-08/09 (business rules + hostname),
    # ASR VULN-04/05/07 (reason codes · EMDs · profile routing),
    # BSP VULN-11 (hostname), Robot V-HI-02 (SABRE endpoint).
    # 10 ocurrencias · el CWE mas frecuente del audit.
    # Foco heuristico · hostnames internos + URLs de environment
    # prefixed · revelan topologia de red y atan el codigo al
    # ambiente. STATIC-CLEARTEXT-LEGACY-IP ya cubre IPs privadas
    # en URLs http:// · este detector complementa.
    (
        "CWE-547",
        re.compile(
            # v1.7.3 · negative lookahead · NO detectar dominios internos
            # canonicos AMX (Route53 PHZ) · son la solucion post-refactor
            # correcta · no un leak. Formato: *.amx.internal · *.amx.com.mx
            r"""(?!["'][a-zA-Z0-9_.-]+\.amx\.(?:internal|com\.mx)["'])"""
            r"""["'][a-zA-Z0-9_-]+"""
            r"""(?:\.[a-zA-Z0-9_-]+)*"""
            r"""\.(?:corp|internal|local|intranet|lan|"""
            r"""miatech|aeromexico|amx|praxis|sabre)"""
            r"""(?:\.[a-zA-Z]{2,})?"""
            r"""(?::\d+)?["']"""
        ),
        "HARDCODED-INTERNAL-HOSTNAME",
        "MEDIUM",
        "Hardcoded · hostname interno/corporativo en string literal",
        _ANY,
    ),
    (
        "CWE-547",
        re.compile(
            r"""["']https?://"""
            r"""(?:staging|qa|uat|dev|stg|prod|preprod|test)"""
            r"""[-.][a-zA-Z0-9.-]+"""
            r"""(?::\d+)?"""
            r"""[/"']"""
        ),
        "HARDCODED-ENV-URL-PREFIX",
        "LOW",
        "Hardcoded · URL con prefijo de environment (staging/qa/prod/dev)",
        _ANY,
    ),
    # ── CWE-256/522 · Credentials Plaintext Storage (5.2 · #7) ───────
    # Referencias audit · Sicofav V-CR-01 (CWE-522 · credenciales en
    # web.config) · cfdis V-CR-02 (CWE-256 · secrets en filesystem).
    # Complementa CWE-798 (que cubre credenciales hardcoded en
    # literales de source code) · este foco es STORAGE persistente
    # sin cifrado.
    (
        "CWE-522",
        re.compile(
            # v1.7.3 · negative lookahead ampliado: arn:aws:secretsmanager,
            # arn:aws:kms, {{ssm:...}}, ${env.*}, @Microsoft.KeyVault son
            # referencias legitimas (la solucion post-refactor) · no
            # credenciales plaintext.
            r"""<add\s+[^>]*\bkey\s*=\s*["'][^"']*"""
            r"""(?:[Pp]assword|[Pp]wd|[Ss]ecret|[Tt]oken|[Aa]pi[Kk]ey|"""
            r"""[Cc]redential|[Pp]rivate[Kk]ey)[^"']*["']\s+"""
            r"""value\s*=\s*["'](?!\{|\$|</?placeholder|</?your|"""
            r"""arn:aws:|@Microsoft\.KeyVault|"""
            r"""\{\{ssm:|ssm://|aws-secret://)"""
            r"""[^"']+["']""",
            re.IGNORECASE,
        ),
        "CREDENTIAL-PLAINTEXT-WEBCONFIG",
        "HIGH",
        "Credenciales plaintext · web.config <add key=... value=...>",
        _NETCFG,
    ),
    (
        "CWE-256",
        re.compile(
            r"""open\s*\(\s*["'][^"']*"""
            r"""(?:password|passwd|secret|credential|api[-_]?key|"""
            r"""token|pwd|\.env|\.pem|private[-_]?key)"""
            r"""[^"']*["']\s*,\s*["'][wa]"""
        ),
        "CREDENTIAL-PLAINTEXT-FILE-WRITE-PY",
        "HIGH",
        "Credential file · open() de archivo credential en modo write/append",
        _PY,
    ),
    (
        "CWE-522",
        re.compile(
            r"""["'][^"']*(?:Server|Data\s+Source|Host)\s*=\s*[^;"']+;"""
            r"""[^"']*(?:Password|Pwd)\s*=\s*"""
            r"""(?!\{|\$|<|%|@|["'])[^;"']{3,}""",
            re.IGNORECASE,
        ),
        "CREDENTIAL-PLAINTEXT-CONNECTION-STRING",
        "HIGH",
        "Credenciales plaintext · connection string con Password=... literal",
        _ANY,
    ),
    # ── CWE-703 · Bare/Silent Exception Handlers (Sprint 5.2 · #8) ───
    # Referencias audit · BSP VULN-07 (RejectionHandler switch empty),
    # cfdis V-CR-03 (sin manejo error SAT), Robot V-HI-03 (sin retry/
    # circuit breaker SABRE), COM-IND V-HI-01 (sin retry Praxis).
    # Silent failures enmascaran bugs · impiden observabilidad.
    (
        "CWE-703",
        re.compile(
            r"""(?m)^\s*except\s*:\s*$|"""
            r"""except\s*(?:\([^)]+\)|BaseException|Exception|\w+)?"""
            r"""\s*(?:as\s+\w+)?\s*:\s*\n\s*pass\s*(?:\n|$)"""
        ),
        "BARE-EXCEPT-HANDLER-PY",
        "MEDIUM",
        "Silent failure · except: bare o except + pass (swallow)",
        _PY,
    ),
    (
        "CWE-703",
        re.compile(
            r"""catch\s*(?:\([^)]*\))?\s*\{\s*\}"""
        ),
        "BARE-EXCEPT-HANDLER-CSHARP",
        "MEDIUM",
        "Silent failure C# · catch{} o catch(Ex){} body vacio",
        _CS,
    ),
    (
        "CWE-703",
        re.compile(
            r"""catch\s*\(\s*[\w.]+(?:\s+\w+)?\s*\)\s*\{\s*\}"""
        ),
        "BARE-EXCEPT-HANDLER-JAVA",
        "MEDIUM",
        "Silent failure Java · catch(Exception e){} body vacio",
        _JAVA,
    ),
    (
        "CWE-703",
        re.compile(
            r"""catch\s*(?:\([^)]*\))?\s*\{\s*\}"""
        ),
        "BARE-EXCEPT-HANDLER-JSTS",
        "MEDIUM",
        "Silent failure JS/TS · catch{} o catch(err){} body vacio",
        _JSTS,
    ),
    (
        "CWE-703",
        re.compile(
            r"""catch\s*\(\s*\\?\w+(?:\\\w+)*\s+\$\w+\s*\)\s*\{\s*\}"""
        ),
        "BARE-EXCEPT-HANDLER-PHP",
        "MEDIUM",
        "Silent failure PHP · catch(Exception $e){} body vacio",
        _PHP,
    ),
    # ── CWE-400 · Uncontrolled Resource Consumption (5.3 · #9) ───────
    # Referencias audit · ARC VULN-04 (sin timeout socket SABRE),
    # BSP VULN-06 (sin timeout Playwright), Robot V-CR-04 (buffer read
    # sin timeout), cfdis V-ME-02 (consumo memoria ilimitado).
    # 7 ocurrencias · foco · llamadas de red/subprocess sin timeout.
    (
        "CWE-400",
        re.compile(
            r"""\brequests\.(?:get|post|put|delete|patch|head|options|request)"""
            r"""\s*\((?![^)]*\btimeout\s*=)[^)]{0,600}\)"""
        ),
        "MISSING-TIMEOUT-REQUESTS-PY",
        "HIGH",
        "No timeout · requests.{get|post|...} sin timeout=",
        _PY,
    ),
    (
        "CWE-400",
        re.compile(
            r"""urllib\.request\.urlopen\s*\((?![^)]*\btimeout\s*=)"""
            r"""[^)]{0,400}\)"""
        ),
        "MISSING-TIMEOUT-URLLIB-PY",
        "HIGH",
        "No timeout · urllib.request.urlopen sin timeout=",
        _PY,
    ),
    (
        "CWE-400",
        re.compile(
            r"""subprocess\.(?:run|call|check_call|check_output|Popen)"""
            r"""\s*\((?![^)]*\btimeout\s*=)[^)]{0,600}\)"""
        ),
        "MISSING-TIMEOUT-SUBPROCESS-PY",
        "MEDIUM",
        "No timeout · subprocess.run/call/Popen sin timeout=",
        _PY,
    ),
    (
        "CWE-400",
        re.compile(
            r"""\bfetch\s*\((?![^)]*(?:signal|AbortSignal|timeout))"""
            r"""[^)]{0,400}\)"""
        ),
        "MISSING-TIMEOUT-FETCH-JSTS",
        "MEDIUM",
        "No timeout · fetch() sin AbortSignal/timeout",
        _JSTS,
    ),
    (
        "CWE-400",
        re.compile(
            r"""\baxios(?:\.(?:get|post|put|delete|patch|head))?"""
            r"""\s*\((?![^)]*\btimeout)[^)]{0,400}\)"""
        ),
        "MISSING-TIMEOUT-AXIOS-JSTS",
        "MEDIUM",
        "No timeout · axios.X() sin timeout",
        _JSTS,
    ),
    # ── CWE-770 · Missing Rate Limit (Sprint 5.3 · #10) ──────────────
    # Referencias audit · ARC VULN-05 (sin rate limit SABRE client) ·
    # BSP VULN-09 (sin rate limit IATA scraper) · ASR VULN-08 (sin
    # rate limit endpoints). 5 ocurrencias.
    # Scope · rutas mutating (POST/PUT/DELETE/PATCH) sin decorator
    # de rate limit. LOW severity · frequently delegated a gateway.
    (
        "CWE-770",
        re.compile(
            r"""@(?:app|router|bp|api)\."""
            r"""(?:route|post|put|delete|patch)\s*\([^)]*\)\s*\n"""
            # Consume cualquier cantidad de decorators NO-limiter
            r"""(?:\s*@(?!(?:limiter\.limit|rate_limit|limit|throttle|"""
            r"""ratelimit|slowapi|throttled))\w[^\n]*\n)*"""
            r"""\s*(?:async\s+)?def\s+\w+\s*\("""
            # FastAPI Depends(RateLimiter) en params cuenta como rate limit
            r"""(?![\s\S]{0,800}?Depends\s*\(\s*\w*"""
            r"""(?:RateLimiter|Throttle|Limit|Throttled))""",
            re.MULTILINE,
        ),
        "MISSING-RATE-LIMIT-FLASK-ROUTE",
        "LOW",
        "No rate limit · Flask/FastAPI route mutating sin @limiter/Depends",
        _PY,
    ),
    (
        "CWE-770",
        re.compile(
            r"""(?:app|router)\.(?:post|put|delete|patch)\s*\(\s*"""
            r"""['"`][^'"`]+['"`]\s*,\s*"""
            # Consume cualquier middleware NO-rateLimit
            r"""(?:(?![\w.]*(?:rateLimit|limiter|throttle|slowDown|"""
            r"""expressRateLimit))\w[\w.]*(?:\s*\([^)]*\))?\s*,\s*)*"""
            r"""(?:async\s*)?(?:\(|function)"""
        ),
        "MISSING-RATE-LIMIT-EXPRESS-ROUTE",
        "LOW",
        "No rate limit · Express route mutating sin middleware rateLimit",
        _JSTS,
    ),
    # ═════════════════════════════════════════════════════════════════
    # v2.5.0 · Cat B detectors derivados del analisis NoShow 25 findings
    # ═════════════════════════════════════════════════════════════════
    (
        "CWE-664",
        re.compile(
            r"""(?s)(?:foreach|for)\s*\([^)]+\)\s*\{[^{}]{0,600}?"""
            r"""\.(?:Remove(?:At)?|Clear)\s*\("""
        ),
        "STATIC-REMOVE-IN-ITERATION-CSHARP",
        "HIGH",
        "Collection modification durante iteracion · InvalidOperationException "
        "en runtime · usar ToList() snapshot o filtro declarativo",
        _CS,
    ),
    (
        "CWE-362",
        re.compile(
            r"""(?:private|public|internal)\s+static\s+"""
            r"""(?!readonly\s+(?:Lazy<|ImmutableDictionary|ImmutableList|"""
            r"""ImmutableArray|ReadOnlyDictionary))"""
            r"""[A-Z]\w+\s+_?[Ii]nstance\b"""
        ),
        "STATIC-SINGLETON-NO-THREADSAFETY-CSHARP",
        "MEDIUM",
        "Singleton static mutable sin Lazy<T> / lock · race condition "
        "potencial bajo concurrencia",
        _CS,
    ),
    (
        "CWE-755",
        re.compile(
            r"""catch\s*\(\s*(?:System\.)?Exception(?:\s+\w+)?\s*\)"""
        ),
        "STATIC-GENERIC-EXCEPTION-CATCH-CSHARP",
        "MEDIUM",
        "Catch generico de Exception · oculta errores especificos · "
        "preferir exceptions tipadas + log estructurado",
        _CS,
    ),
    (
        "CWE-1176",
        re.compile(r"""\.ToList\(\)"""),
        "STATIC-EXCESSIVE-TOLIST-CSHARP",
        "LOW",
        "Materializacion eager de IEnumerable · memory/CPU overhead si "
        "se encadena · evaluar si se puede mantener lazy",
        _CS,
    ),
    (
        "CWE-1188",
        re.compile(
            r"""\b(?:Soap|Sabre|SFTP|WebService|Session)\w*"""
            r"""(?:Client|Adapter)\.\w+\s*\("""
        ),
        "STATIC-MISSING-RETRY-EXTERNAL-CALL-CSHARP",
        "MEDIUM",
        "Llamada a servicio externo (Sabre/SFTP/SOAP Client/Adapter) · "
        "verificar wrapper de retry (Polly / try-retry-backoff) · "
        "fallas transitorias no mitigadas",
        _CS,
    ),
    # ═════════════════════════════════════════════════════════════════
    # v3.1 · Detectores derivados de clean-session validation (2026-04-23)
    # ═════════════════════════════════════════════════════════════════
    (
        "CWE-532",
        re.compile(
            r"""\b(?:log|Log|logger|_log|_logger)"""
            r"""(?:4net)?\.(?:Info|Debug|Warn|Error|Fatal|Trace)\b[^;]*"""
            r"""(?:password|passwd|secret|token|securityToken|apikey|"""
            r"""api_key|credential|passPhrase|privateKey)""",
            re.IGNORECASE,
        ),
        "STATIC-SENSITIVE-LOG-CSHARP",
        "HIGH",
        "Logging de credencial/token/secret · CWE-532 · CWE-312 · "
        "redact antes de emitir al log (log4net enricher o Serilog "
        "destructuring)",
        _CS,
    ),
    (
        "CWE-532",
        re.compile(
            r"""\b(?:log|Log|logger|_log|_logger)"""
            r"""(?:4net)?\.(?:Info|Debug|Warn|Error|Fatal)\b[^;]*"""
            r"""(?:passengerName|pnr|PNR|ticketNumber|customerId|"""
            r"""curp|rfc|passport|creditCard|cardNumber)""",
        ),
        "STATIC-PII-LOG-CSHARP",
        "HIGH",
        "Logging de PII (passenger · PNR · ticket · customer ID · CURP · "
        "passport · card) · CWE-532 · LFPDPPP violation · redact o "
        "migrar a Serilog con enricher PII-aware",
        _CS,
    ),
    (
        "CWE-295",
        re.compile(
            r"""new\s+SftpClient\s*\([^)]*\)"""
        ),
        "STATIC-SFTP-NO-HOSTKEY-VERIFICATION-CSHARP",
        "HIGH",
        "SftpClient sin HostKeyReceived handler · sin verificacion · "
        "MITM susceptible · CWE-295 · agregar "
        "client.HostKeyReceived += (s,e) => {e.CanTrust = ...}",
        _CS,
    ),
    (
        "CWE-319",
        re.compile(
            # v3.3.2 fix · solo flag si NO hay evidencia de TLS en el mismo archivo
            # (EnableSsl · StartTls · SecureSocketOptions) · scope-aware heuristic
            r"""new\s+SmtpClient\s*\([^)]*\)(?![\s\S]{0,2000}?"""
            r"""(?:EnableSsl\s*=\s*true|"""
            r"""SecureSocketOptions\.(?:StartTls|SslOnConnect|Auto)|"""
            r"""\.ConnectAsync\s*\([^)]*(?:587|StartTls|Ssl)))"""
        ),
        "STATIC-SMTP-NO-TLS-CSHARP",
        "MEDIUM",
        "SmtpClient construido sin evidencia de TLS en el archivo · "
        "verificar EnableSsl=true · SecureSocketOptions.StartTls · o "
        "ConnectAsync(..., 587, StartTls) · cleartext SMTP viola retro "
        "20-abr · CWE-319 · v3.3.2 scope-aware",
        _CS,
    ),
    (
        "CWE-209",
        re.compile(
            r"""\{(?:ex|exception|e)\.(?:StackTrace|ToString)\}|"""
            r"""\+\s*(?:ex|exception|e)\.(?:StackTrace|ToString)\(\)"""
        ),
        "STATIC-EXCEPTION-DETAILS-EXPOSURE-CSHARP",
        "HIGH",
        "Stack trace / exception details expuestos en string "
        "interpolation (email body · response · UI) · CWE-209 · "
        "disclosure de paths internos · assembly names · SQL fragments",
        _CS,
    ),
    (
        "CWE-755",
        re.compile(r"""throw\s+ex\s*;"""),
        "STATIC-THROW-EX-DESTROYS-STACK-CSHARP",
        "MEDIUM",
        "'throw ex' destruye stack trace original · usar 'throw;' "
        "para preservar · CWE-755 error handling antipattern",
        _CS,
    ),
    # ═════════════════════════════════════════════════════════════════
    # v3.1.1 · Detectores nuevos de 2nd clean-session validation
    # ═════════════════════════════════════════════════════════════════
    (
        "CWE-697",
        re.compile(
            r"""\.(?:Subtract|Add)\s*\([^)]+\)\s*\.Hours\b(?!\s*\.TotalHours)|"""
            r"""TimeSpan[^.]*\.Hours\b(?!\s*\.TotalHours)|"""
            r"""\w+\.(?:Hours|Minutes|Seconds|Days)\b\s*(?:<|>|<=|>=|==|!=)\s*\d"""
        ),
        "STATIC-TIMESPAN-HOURS-MISUSE-CSHARP",
        "HIGH",
        "TimeSpan.Hours retorna componente 0-23 · NO total · "
        "para ventana >24h usar .TotalHours · CWE-697 incorrect "
        "comparison · bug silencioso revenue-crítico",
        _CS,
    ),
    (
        "CWE-547",
        re.compile(
            r"""(?:host|endpoint|server|ipAddress|address|value)\s*=\s*"""
            r"""["']?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?["']?""",
            re.IGNORECASE,
        ),
        "STATIC-IP-LITERAL-IN-CONFIG",
        "HIGH",
        "IP literal (v4) en atributo de config · viola DNS-first · "
        "usar Route53 PHZ interno · CWE-547 · CWE-1104",
        frozenset({".config", ".xml", ".appsettings"}),
    ),
    (
        "CWE-354",
        re.compile(
            r"""\.(?:FirstName|firstName|first_name)\.(?:Contains|IndexOf|"""
            r"""StartsWith)\([^)]+\)[^}]{0,80}?"""
            r"""\.(?:LastName|lastName|last_name)\.(?:Contains|IndexOf|StartsWith)\(|"""
            r"""\.(?:LastName|lastName|last_name)\.(?:Contains|IndexOf|"""
            r"""StartsWith)\([^)]+\)[^}]{0,80}?"""
            r"""\.(?:FirstName|firstName|first_name)\.(?:Contains|IndexOf|StartsWith)\("""
        ),
        "STATIC-SUBSTRING-NAME-MATCHING-CSHARP",
        "HIGH",
        "Substring matching sobre firstName + lastName (.Contains) es "
        "antipattern de identidad · 'MARIA' matchea 'MARIAL' · "
        "ticket asignado a pax erróneo · CWE-354 · usar equality o "
        "PNR/ticketNumber único",
        _CS,
    ),
    # ═════════════════════════════════════════════════════════════════
    # v3.4.0 · Detectores derivados de BO-AMX/amazon-q-rules (35 reglas)
    # Alineación AIOS ↔ AMX oficial · bloqueantes pre-deploy retro 20-abr
    # ═════════════════════════════════════════════════════════════════
    (
        "CWE-311",
        re.compile(
            r"""alias/aws/(?:s3|rds|lambda|dynamodb|sqs|sns|kms|secretsmanager|"""
            r"""ebs|ssm|cloudwatch|cloudtrail|backup|xray)|"""
            r"""kms\.Alias\.from_alias_name\s*\([^)]*["']alias/aws/"""
        ),
        "AMX-CDK-KMS-AWS-MANAGED-FORBIDDEN",
        "CRITICAL",
        "KMS aws-managed key · prohibido por retro 20-abr y amazon-q-rules G01 "
        "· usar CMK dedicada CSOC · CWE-311",
        frozenset({".py", ".ts", ".js", ".json", ".yaml", ".yml"}),
    ),
    (
        "CWE-778",
        re.compile(
            r"""class\s+\w+\s*\(\s*Stack\s*\)"""
        ),
        "AMX-CDK-STACK-REQUIRES-MANDATORY-TAGS",
        "MEDIUM",
        "Stack CDK detectado · verificar que incluye los 8 tags obligatorios "
        "AMX (CentroDeCosto · DuenoDeLaCuenta · Proyecto · Ambiente · "
        "ImpactoANegocio · Aplicacion · GrupoDeParcheo · SistemaOperativo) "
        "· amazon-q-rules G02",
        frozenset({".py"}),
    ),
    (
        "CWE-311",
        re.compile(
            # Solo firefly si usa S3_MANAGED explícito (AWS-managed keys) ·
            # no firefly 'encryption=BucketEncryption.KMS' ni 'encryption_key=cmk'
            # v3.4.0 · regex simple · false negatives tolerable · deep review catch rest
            r"""encryption\s*=\s*(?:s3\.)?BucketEncryption\.S3_MANAGED|"""
            r"""encryption\s*=\s*(?:s3\.)?BucketEncryption\.UNENCRYPTED"""
        ),
        "AMX-S3-MISSING-KMS-ENCRYPTION",
        "HIGH",
        "S3 bucket con encryption S3_MANAGED o UNENCRYPTED · amazon-q-rules G03 "
        "requiere KMS CMK (BucketEncryption.KMS + encryption_key=cmk) · CWE-311",
        frozenset({".py"}),
    ),
    (
        "CWE-272",
        re.compile(
            r"""iam\.Role\s*\([^)]*role_name\s*=\s*["'](?!amx-r-|AMX-R-)[^"']+["']"""
        ),
        "AMX-IAM-ROLE-WRONG-PREFIX",
        "HIGH",
        "IAM role sin prefijo amx-r-* / AMX-R-* · amazon-q-rules G05 "
        "requirement duro · CWE-272",
        frozenset({".py"}),
    ),
    (
        "CWE-710",
        re.compile(
            r"""^\s*(?:cdk|npx\s+cdk)\s+(?:deploy|bootstrap|synth|destroy|diff)""",
            re.MULTILINE,
        ),
        "AMX-CDK-DIRECT-COMMAND",
        "MEDIUM",
        "Script invoca 'cdk' directo · amazon-q-rules CS03 requiere "
        "'cdk-admin.py --env {de|q|pd}' como wrapper estándar",
        frozenset({".sh", ".ps1", ".bat", ".yml", ".yaml"}),
    ),
    (
        "CWE-269",
        re.compile(
            r"""["']Resource["']\s*:\s*["']\*["']|"""
            r"""["']Action["']\s*:\s*["']\*["']|"""
            r"""iam\.PolicyStatement\s*\([^)]*resources\s*=\s*\[\s*["']\*["']\s*\]|"""
            r"""iam\.PolicyStatement\s*\([^)]*actions\s*=\s*\[\s*["']\*["']\s*\]"""
        ),
        "AMX-IAM-WILDCARD-POLICY",
        "HIGH",
        "IAM policy con Resource:* o Action:* · viola least-privilege · "
        "amazon-q-rules G07 · CWE-269",
        frozenset({".py", ".json", ".yaml", ".yml", ".ts"}),
    ),
    # ═════════════════════════════════════════════════════════════════
    # v3.5.0 sprint 2 · 4 detectores refinados AMX · patrones observados
    # en baseline 6 apps Revenue Accounting (23-abr-2026)
    # ═════════════════════════════════════════════════════════════════
    (
        "CWE-319",
        re.compile(
            # URL literal con IPv4 hardcoded (no CIDR en comentarios):
            # http://10.0.1.5:8443/... o https://172.16.20.10/Notify
            r"""["']https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"""
            r"""(?::\d{1,5})?/[^"'\s]*["']"""
        ),
        "AMX-VBNET-HARDCODED-IP-IN-URL",
        "HIGH",
        "URL literal con IP hardcoded en VB.NET · endpoint interno "
        "cableado (SABRE/notify) · rotar a config + DNS · CWE-319",
        _VB,
    ),
    (
        "CWE-522",
        re.compile(
            # Connection string literal con credencial en DBCnx.vb-style:
            # "Server=XXX;Database=Y;User Id=Z;Password=W"
            # Match cuando aparece Server=/Data Source= junto con Password=
            # en la misma línea · evita FPs en docs/xml literales.
            r"""["'](?:[^"'\n]*?\b(?:Server|Data\s+Source|Host)\s*=\s*"""
            r"""[^;"']+;[^"'\n]*?\bPassword\s*=\s*[^"';\s]+)[^"'\n]*["']"""
        ),
        "AMX-DBCNX-VB-HARDCODED-CONNSTR",
        "HIGH",
        "Connection string literal con Password inline en VB.NET · "
        "mover a AWS Secrets Manager · amazon-q-rules security · "
        "CWE-522",
        _VB,
    ),
    (
        "CWE-522",
        re.compile(
            # appsettings.json con sección ConnectionStrings que tiene
            # un valor literal con Server=/Data Source=/Host= (o password)
            # · NO dispara si el valor es un token $SECRETSMANAGER- /
            # $ENV: / {{ }} / ${ } (placeholders de injection).
            r""""ConnectionStrings"\s*:\s*\{[^}]*?"""
            r""""[^"]+"\s*:\s*"(?!\$SECRETSMANAGER|\$\{|\{\{|\$ENV:)"""
            r"""[^"]*?(?:\bServer\s*=|\bData\s+Source\s*=|\bHost\s*=|"""
            r"""\bPassword\s*=|\bPwd\s*=)[^"]*"""
            r""""[^}]*\}""",
            re.DOTALL,
        ),
        "AMX-APPSETTINGS-CONNSTR-NO-SECRETS-MANAGER",
        "HIGH",
        "appsettings.json con ConnectionStrings literal · sin token "
        "Secrets Manager ($SECRETSMANAGER-...) · riesgo commit de "
        "credencial · amazon-q-rules security · CWE-522",
        _APPSETTINGS,
    ),
    (
        "CWE-1104",
        re.compile(
            # .csproj / .vbproj con TargetFramework[Version] EOL
            # (anteriores a .NET 4.8 · Microsoft EOL support).
            r"""<TargetFramework(?:Version)?>\s*v?"""
            r"""(?:1\.\d|2\.\d|3\.\d|4\.0|4\.5(?:\.\d)?|4\.6(?:\.\d)?|"""
            r"""4\.7(?:\.\d)?)\s*</TargetFramework(?:Version)?>"""
        ),
        "AMX-NETFX-EOL-HIGH",
        "HIGH",
        ".NET Framework EOL (≤ v4.7) · Microsoft no soporta · "
        "migrar a .NET 8 LTS (o mínimo 4.8.1) · CWE-1104",
        _PROJ,
    ),
    # ═════════════════════════════════════════════════════════════════
    # v3.5.0 sprint 3 · 2 detectores amazon-q-rules gaps (23-abr-2026)
    # (AMX-CDK-WRAPPER-MISSING se implementa como check en stacks/aws)
    # ═════════════════════════════════════════════════════════════════
    (
        "CWE-1357",
        re.compile(
            # Naming de recurso CDK sin sufijo dinámico de ambiente.
            # Matchea props de naming (bucket_name, function_name, etc.)
            # asignados a string literal sin f-string ni concat de env.
            r"""\b(?:bucket_name|function_name|queue_name|topic_name|"""
            r"""table_name|repository_name|role_name|policy_name|"""
            r"""user_pool_name|stream_name|cluster_name|service_name|"""
            r"""log_group_name)\s*=\s*["'][A-Za-z0-9_\-]+["']"""
        ),
        "AMX-RESOURCE-SUFFIX-MISSING",
        "MEDIUM",
        "Recurso CDK con naming literal sin sufijo dinámico "
        "'-{env}' (de/q/pd) · amazon-q-rules G04 · "
        "usar f-string o Fn.sub con parámetro de ambiente",
        frozenset({".py", ".ts"}),
    ),
    (
        "CWE-1104",
        re.compile(
            # CloudFront Origin Access Identity (OAI) deprecated ·
            # amazon-q-rules G09 · preferir Origin Access Control (OAC).
            r"""\bCfnCloudFrontOriginAccessIdentity\b|"""
            r"""\bcloudfront\.OriginAccessIdentity\b|"""
            r"""origin_access_identity\s*=|"""
            r"""origin_access_identities\s*="""
        ),
        "AMX-CLOUDFRONT-OAI-DEPRECATED",
        "MEDIUM",
        "CloudFront Origin Access Identity (OAI) deprecated · "
        "migrar a Origin Access Control (OAC) · amazon-q-rules G09 · "
        "CWE-1104",
        frozenset({".py", ".ts", ".js"}),
    ),
    # ═════════════════════════════════════════════════════════════════
    # v3.6.0 · P0 gaps para scope eTride (24-abr-2026)
    # G-11 · master password hardcoded used for decryption
    # G-NEW-1 · api-standars.md OpenAPI 3.0 + camelCase
    # (G-06 coverage gate se implementa como subcomando CLI separado)
    # Evidencia: SIC-NEW-01 M14t3ch@01 en SICOFAV/Decrypt/cDecrypt.cs:14
    # no detectado por AIOS v3.5.1 "Hardcoded credentials (0)" falso
    # negativo · cross-check 23-abr tarde user-driven.
    # ═════════════════════════════════════════════════════════════════
    (
        "CWE-798",
        re.compile(
            # Master password/key hardcoded en .cs · usado por módulos
            # Decrypt custom que cifran connection strings. Patron:
            #   static (readonly)? string (password|masterKey|...) = "...";
            # Evidencia SIC-NEW-01: 'M14t3ch@01' en Decrypt/cDecrypt.cs.
            # Min 4 chars en valor (evita FP con string vacío "" o "x").
            # IGNORECASE para capturar camelCase · PascalCase · snake_case.
            r"""\bstatic\s+(?:readonly\s+)?string\s+"""
            r"""(?:password|passwd|pwd|master[_]?key|encryption[_]?key|"""
            r"""secret[_]?key|api[_]?key|aes[_]?key|passphrase|"""
            r"""decrypt[_]?key|crypto[_]?key)"""
            r"""\s*=\s*["'][^"'\s]{4,}["']\s*;""",
            re.IGNORECASE,
        ),
        "AMX-DOTNET-HARDCODED-DECRYPT-KEY",
        "CRITICAL",
        "Master password/key hardcoded en .cs · típicamente usado por "
        "módulo Decrypt custom para descifrar connection strings · "
        "invalida mitigación 'credenciales encriptadas' · migrar a "
        "AWS Secrets Manager · CWE-798 + CWE-321",
        _CS,
    ),
    (
        "CWE-760",
        re.compile(
            # Salt predecible en arrays byte[] · usado con
            # Rfc2898DeriveBytes/PasswordDeriveBytes.
            # Patterns: {1,2,3,4,5,6,7,8} · {0,0,0,0,...} · new byte[8]
            # Requiere contexto ("salt" en nombre de variable) para FP-safe.
            r"""\b(?:salt|saltBytes|saltArray)\b[^=]{0,50}=\s*"""
            r"""new\s+byte\s*\[\s*\]\s*\{\s*(?:0x[0-9A-Fa-f]+|\d+)"""
            r"""\s*(?:,\s*(?:0x[0-9A-Fa-f]+|\d+)\s*){2,31}\}"""
        ),
        "AMX-DOTNET-PREDICTABLE-SALT",
        "HIGH",
        "Salt predecible (byte[] literal con secuencia lineal o "
        "zeros) usado para derivación de clave · debe ser aleatorio "
        "per-secret y almacenado con el ciphertext · CWE-760",
        _CS,
    ),
    # G-NEW-1 · ApiController attribute check · deferred to v3.6.1 ·
    # requiere function-based post-processor con lookback context
    # (regex lineal produce FP porque [ApiController] suele estar 1-3
    # líneas arriba de la declaración class · difícil con regex simple).
    # Tracking: AIOS_GAPS_FROM_BLOCK1.md G-NEW-1 deferred.
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


def _match_exclude_files(
    path: Path, root: Path, patterns: list[str],
) -> bool:
    """v1.7.2 · soporta glob patterns en exclude_files.

    Cada pattern puede ser:
    - Nombre exacto · "aios-config.json" (legacy · compat v1.x)
    - Glob con wildcards · "tools/*", "tools/**", "*.generated.*"
    - Ruta relativa · "apps/legacy/web.config"

    Matches contra filename, relative-to-root, y full path. Retorna True
    si el archivo debe ser excluido.
    """
    import fnmatch
    if not patterns:
        return False
    name = path.name
    try:
        rel = str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        rel = str(path).replace("\\", "/")
    for pat in patterns:
        if not pat:
            continue
        pat_norm = pat.replace("\\", "/")
        # Detectar si el pattern es glob (tiene wildcards)
        has_wild = any(c in pat_norm for c in "*?[")
        if has_wild:
            # Glob match contra filename + relative path
            if fnmatch.fnmatch(name, pat_norm) or fnmatch.fnmatch(rel, pat_norm):
                return True
            # v1.7.2 · "**/" matchea recursivo · fnmatch no lo hace nativamente
            if "**" in pat_norm:
                # Normalizar "foo/**/bar" a "foo/*/bar" y "foo/**" a "foo/*"
                simple = pat_norm.replace("**/", "").replace("/**", "")
                if simple and fnmatch.fnmatch(rel, f"*{simple}*"):
                    return True
        else:
            # Match exacto (comportamiento legacy v1.x)
            if name == pat_norm or rel == pat_norm:
                return True
    return False


def _walk_files(root: Path, config: dict):
    skip_dirs = set(config.get("exclude_dirs", []))
    skip_exts = set(config.get("exclude_exts", []))
    skip_files_raw = config.get("exclude_files", [])
    max_size = int(config.get("max_file_size_bytes", 2 * 1024 * 1024))
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        # v3.5.0 · match por nombre completo para soportar dobles-suffix
        # como .min.js / .min.css (path.suffix solo retorna el último).
        name_lc = path.name.lower()
        if any(name_lc.endswith(ext) for ext in skip_exts):
            continue
        if _match_exclude_files(path, root, skip_files_raw):
            continue
        try:
            if path.stat().st_size > max_size:
                continue
        except OSError:
            continue
        yield path


def scan_directory(root: Path, config: Optional[dict] = None) -> list[Finding]:
    """Scan `root` con detectores embedded + forbidden literals.

    v1.8.0 · RFC-003 Nivel 1 · si existe ontology (policy dir o
    amx-domain-ontology.yaml en root), cada finding emitido queda
    clasificado (bug · business_rule · migration_candidate · unclear)
    y con accion recomendada (auto_fix · pause_for_review · skip · warn).

    v1.9.0 · RFC-003 Nivel 2 · si llm_classifier.enabled=true en config,
    findings con ontology_action=pause_for_review son re-evaluados por
    LLM (Claude/GPT/Ollama) con context (code + git blame + cross-file).
    Override de decisión si confidence >= threshold.
    """
    cfg = config or _load_config(root)
    findings: list[Finding] = []
    forbidden = [lit for lit in cfg.get("forbidden_literals", []) if lit]
    skip_comments = bool(cfg.get("exclude_comment_lines", True))
    # v1.8.0 · load domain ontology (opcional · no-op si no existe)
    ontology = _load_ontology_for_scan(root, cfg)
    # v1.9.0 · load LLM classifier (opt-in · no-op si disabled)
    llm_classifier = _load_llm_classifier(cfg)

    for fp in _walk_files(root, cfg):
        try:
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        rel = str(fp.relative_to(root))
        fp_ext = fp.suffix.lower()
        lines_cache = content.splitlines()
        # v1.7.3 · content sanitizado (comentarios reemplazados por
        # espacios preservando offsets) para evitar FPs donde regex
        # multi-linea capturan patterns citados en comentarios.
        scan_content = (
            _strip_inline_comments(content, fp_ext)
            if skip_comments else content
        )

        def _emit_unless_comment(finding: Finding) -> None:
            """v1.7.2 · skip findings que caen en lineas de comentario.

            v1.8.0 · RFC-003 Nivel 1 · enrich con domain ontology.
            v1.9.0 · RFC-003 Nivel 2 · LLM classifier para findings
            que Nivel 1 marcó como pause_for_review.
            """
            if skip_comments and 0 < finding.line <= len(lines_cache):
                if _is_comment_line(lines_cache[finding.line - 1], fp_ext):
                    return
            # v1.8.0 · Nivel 1 · ontology classification
            _enrich_finding_with_ontology(finding, ontology)
            # v1.9.0 · Nivel 2 · LLM re-classification (opt-in · solo pause)
            _enrich_finding_with_llm(finding, root, llm_classifier)
            findings.append(finding)

        for cwe, pattern, rule_id, severity, desc, file_exts in _DETECTORS:
            if file_exts is not None and fp_ext not in file_exts:
                continue
            # v1.7.3 · detector regex opera sobre content sin comentarios
            for m in pattern.finditer(scan_content):
                line_no = scan_content.count("\n", 0, m.start()) + 1
                snippet = lines_cache[line_no - 1].strip()[:160] if line_no - 1 < len(lines_cache) else ""
                # v3.5.0 · degradar catch genérico a LOW si hay logging
                eff_severity = severity
                if rule_id == "STATIC-GENERIC-EXCEPTION-CATCH-CSHARP" and \
                        _catch_block_has_logging(scan_content, m.end()):
                    eff_severity = "LOW"
                _emit_unless_comment(Finding(
                    cwe=cwe, severity=eff_severity, rule_id=rule_id,
                    file=rel, line=line_no, snippet=snippet,
                ))

        # forbidden_literals siguen usando content original (v1.7.2
        # el line-by-line filter es suficiente · los literals no
        # cruzan lineas).
        for literal in forbidden:
            for m in re.finditer(re.escape(literal), content):
                line_no = content.count("\n", 0, m.start()) + 1
                _emit_unless_comment(Finding(
                    cwe="CWE-798", severity="CRITICAL",
                    rule_id=f"FORBIDDEN-LITERAL-{literal[:20]}",
                    file=rel, line=line_no, snippet=literal,
                ))

    return findings


# ---------------------------------------------------------------------------
# v1.8.0 · RFC-003 · helpers de domain ontology
# ---------------------------------------------------------------------------

def _load_ontology_for_scan(root: Path, cfg: dict) -> dict:
    """Busca ontology en orden: cfg['ontology_path'] · root/amx-domain-ontology.yaml
    · policies/<policy>/ontology.yaml. Retorna dict vacio si no hay.
    """
    try:
        from .ontology import load_ontology
    except ImportError:
        return {}

    # 1. Explicit path en config
    ontology_path = cfg.get("ontology_path")
    if ontology_path:
        p = Path(ontology_path)
        if not p.is_absolute():
            p = root / p
        return load_ontology(p)

    # 2. Root-level convention
    convention = root / "amx-domain-ontology.yaml"
    if convention.exists():
        return load_ontology(convention)

    # 3. Policy-scoped ontology
    policy_name = cfg.get("policy", "amx-revenue-accounting")
    # Buscar en el package instalado (aios/policies/<policy>/ontology.yaml)
    try:
        import aios.policies as _ap
        policy_dir = Path(_ap.__file__).parent / policy_name
        ont_file = policy_dir / "ontology.yaml"
        if ont_file.exists():
            return load_ontology(ont_file)
    except Exception:  # noqa: BLE001
        pass

    return {"patterns": [], "default_action": "auto_fix",
            "default_classification": "unclear"}


def _enrich_finding_with_ontology(finding: Finding, ontology: dict) -> None:
    """v1.8.0 · muta el finding in-place con ontology classification."""
    if not ontology or not ontology.get("patterns"):
        # Sin ontology · deja defaults (auto_fix · unclear)
        return
    try:
        from .ontology import classify_finding
    except ImportError:
        return
    try:
        result = classify_finding(finding, ontology)
        finding.ontology_action = result.action
        finding.ontology_match = result.ontology_match
        finding.ontology_classification = result.classification
        finding.ontology_message = result.message
    except Exception:  # noqa: BLE001 · classify failures no deben romper scan
        pass


# ---------------------------------------------------------------------------
# v1.9.0 · RFC-003 Nivel 2 · LLM classifier helpers
# ---------------------------------------------------------------------------

def _load_llm_classifier(cfg: dict):
    """Crea LLMClassifier desde config si enabled · None si opt-out."""
    llm_cfg = (cfg or {}).get("llm_classifier") or {}
    if not llm_cfg.get("enabled", False):
        return None
    try:
        from .llm_classifier import LLMClassifier
        return LLMClassifier.from_config(llm_cfg)
    except ImportError:
        return None
    except Exception:  # noqa: BLE001 · init failures no deben romper scan
        return None


def _enrich_finding_with_llm(
    finding: Finding, root: Path, classifier,
) -> None:
    """v1.9.0 · si classifier está disponible y el finding tiene
    ontology_action=pause_for_review, invoca LLM para re-clasificar.
    Si confidence >= threshold, override la decision del Nivel 1.
    """
    if classifier is None:
        return
    # Solo invocar LLM para findings que Nivel 1 dejó ambiguos
    if finding.ontology_action != "pause_for_review":
        return
    try:
        result = classifier.classify(finding, root)
    except Exception:  # noqa: BLE001
        return
    # Guardar siempre el output del LLM (audit trail)
    finding.llm_classification = result.classification
    finding.llm_confidence = result.confidence
    finding.llm_reasoning = result.reasoning
    finding.llm_evidence = list(result.evidence)
    finding.llm_provider = result.provider
    finding.llm_cached = result.cached
    # Override Nivel 1 solo si high confidence
    if result.confidence >= classifier.confidence_threshold:
        finding.ontology_action = result.recommended_action
        finding.ontology_classification = result.classification
        finding.ontology_message = (
            f"[LLM override · conf={result.confidence:.2f}] {result.reasoning}"
        )


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
    skip_files_raw = cfg.get("exclude_files", [])
    skip_comments = bool(cfg.get("exclude_comment_lines", True))
    # v1.8.0 · RFC-003 Nivel 1 · load ontology
    ontology = _load_ontology_for_scan(root, cfg)
    # v1.9.0 · RFC-003 Nivel 2 · load LLM classifier (opt-in)
    llm_classifier = _load_llm_classifier(cfg)

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
        # v3.5.0 · match por nombre completo para soportar dobles-suffix
        name_lc = fp.name.lower()
        if any(name_lc.endswith(ext) for ext in skip_exts):
            continue
        if _match_exclude_files(fp, root, skip_files_raw):
            continue
        try:
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        fp_ext = fp.suffix.lower()
        lines_cache = content.splitlines()
        # v1.7.3 · content sanitizado para detectores (ver scan_directory)
        scan_content = (
            _strip_inline_comments(content, fp_ext)
            if skip_comments else content
        )

        def _emit_unless_comment(finding: Finding) -> None:
            if skip_comments and 0 < finding.line <= len(lines_cache):
                if _is_comment_line(lines_cache[finding.line - 1], fp_ext):
                    return
            _enrich_finding_with_ontology(finding, ontology)
            _enrich_finding_with_llm(finding, root, llm_classifier)
            findings.append(finding)

        for cwe, pattern, rule_id, severity, desc, file_exts in _DETECTORS:
            if file_exts is not None and fp_ext not in file_exts:
                continue
            for m in pattern.finditer(scan_content):
                line_no = scan_content.count("\n", 0, m.start()) + 1
                snippet = (
                    lines_cache[line_no - 1].strip()[:160]
                    if line_no - 1 < len(lines_cache) else ""
                )
                # v3.5.0 · degradar catch genérico a LOW si hay logging
                eff_severity = severity
                if rule_id == "STATIC-GENERIC-EXCEPTION-CATCH-CSHARP" and \
                        _catch_block_has_logging(scan_content, m.end()):
                    eff_severity = "LOW"
                _emit_unless_comment(Finding(
                    cwe=cwe, severity=eff_severity, rule_id=rule_id,
                    file=file_rel, line=line_no, snippet=snippet,
                ))

        for literal in forbidden:
            for m in re.finditer(re.escape(literal), content):
                line_no = content.count("\n", 0, m.start()) + 1
                _emit_unless_comment(Finding(
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

    # v1.8.0 · RFC-003 Nivel 1 · recolecta findings que requieren review humano
    # v1.9.0 · RFC-003 Nivel 2 · incluye reasoning del LLM si hubo override
    requires_review: list[dict] = []
    ontology_counts: dict[str, int] = {}
    llm_overrides = 0
    for f in findings:
        action = getattr(f, "ontology_action", "auto_fix")
        ontology_counts[action] = ontology_counts.get(action, 0) + 1
        if getattr(f, "llm_classification", None) is not None:
            llm_overrides += 1
        if action == "pause_for_review":
            entry = {
                "rule_id": f.rule_id,
                "file": f.file,
                "line": f.line,
                "severity": f.severity,
                "ontology_match": getattr(f, "ontology_match", None),
                "classification": getattr(f, "ontology_classification", "unclear"),
                "message": getattr(f, "ontology_message", ""),
            }
            # v1.9.0 · enrich con LLM output si disponible
            if getattr(f, "llm_classification", None):
                entry["llm"] = {
                    "classification": f.llm_classification,
                    "confidence": f.llm_confidence,
                    "reasoning": f.llm_reasoning,
                    "evidence": list(f.llm_evidence),
                    "provider": f.llm_provider,
                    "cached": f.llm_cached,
                }
            requires_review.append(entry)

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
        # v1.8.0 · RFC-003 Nivel 1 · ontology outputs
        "requires_human_review": requires_review,
        "ontology_counts": ontology_counts,
        # v1.9.0 · RFC-003 Nivel 2 · LLM classifier metrics
        "llm_overrides": llm_overrides,
    }
