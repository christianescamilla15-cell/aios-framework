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
                     "dist", "build", ".pytest_cache", ".mypy_cache"],
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


# (cwe, pattern, rule_id, severity, description)
_DETECTORS: list[tuple[str, re.Pattern, str, str, str]] = [
    (
        "CWE-89",
        re.compile(r"""\.execute\(\s*f['"]"""),
        "STATIC-SQL-FSTRING",
        "CRITICAL",
        "SQL injection · f-string en cursor.execute",
    ),
    (
        "CWE-89",
        re.compile(r"""\.execute\(\s*(?:"[^"\n]*"|'[^'\n]*')\s*\+"""),
        "STATIC-SQL-CONCAT",
        "CRITICAL",
        "SQL injection · string concat en cursor.execute",
    ),
    (
        "CWE-78",
        re.compile(r"""subprocess\.[a-z]+\([^)]*shell\s*=\s*True"""),
        "STATIC-CMD-SHELL-TRUE",
        "CRITICAL",
        "Command injection · subprocess con shell=True",
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
    ),
    (
        "CWE-319",
        re.compile(r"""['"]http://(?:172\.|10\.|192\.168)"""),
        "STATIC-CLEARTEXT-LEGACY-IP",
        "HIGH",
        "Clear-text · HTTP (no HTTPS) a IP legacy interna",
    ),
    (
        "CWE-287",
        re.compile(r"""if\s+\w+\s+is\s+None\s*:\s*\n\s*return\s+True"""),
        "STATIC-AUTH-BYPASS-NONE",
        "HIGH",
        "Auth bypass · header ausente retorna True",
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
    ),
    (
        "CWE-502",
        re.compile(r"""pickle\.(loads?|load)\("""),
        "STATIC-PICKLE-DESERIALIZATION",
        "CRITICAL",
        "Insecure deserialization · pickle.load(s)",
    ),
    (
        "CWE-611",
        re.compile(r"""resolve_entities\s*=\s*True|load_dtd\s*=\s*True"""),
        "STATIC-XXE-LXML",
        "HIGH",
        "XXE · lxml XMLParser con resolve_entities/load_dtd=True",
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
    ),
    (
        "CWE-78",
        re.compile(r"""UseShellExecute\s*=\s*true""", re.IGNORECASE),
        "STATIC-CMD-CSHARP-SHELL-EXECUTE",
        "CRITICAL",
        "Command injection C# · UseShellExecute=true",
    ),
    (
        "CWE-79",
        re.compile(r"""Response\.Write\s*\(\s*Request\.(?:Params|Query|Form)"""),
        "STATIC-XSS-CSHARP-RESPONSE-WRITE",
        "HIGH",
        "Reflected XSS C# · Response.Write sobre Request.*",
    ),
    (
        "CWE-502",
        re.compile(r"""BinaryFormatter|NetDataContractSerializer"""),
        "STATIC-DESERIALIZATION-CSHARP",
        "CRITICAL",
        "Insecure deserialization C# · BinaryFormatter",
    ),
    (
        "CWE-611",
        re.compile(r"""XmlResolver\s*=\s*new\s+XmlUrlResolver"""),
        "STATIC-XXE-CSHARP-XMLRESOLVER",
        "HIGH",
        "XXE C# · XmlDocument con XmlUrlResolver",
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
    ),
    (
        "CWE-78",
        re.compile(r"""Runtime\.getRuntime\(\)\.exec\s*\("""),
        "STATIC-CMD-JAVA-RUNTIME-EXEC",
        "CRITICAL",
        "Command injection Java · Runtime.getRuntime().exec()",
    ),
    (
        "CWE-79",
        re.compile(
            r"""\.getWriter\(\)\.(?:print|write|println)\s*\([^)]*request\.getParameter"""
        ),
        "STATIC-XSS-JAVA-WRITER",
        "HIGH",
        "Reflected XSS Java · getWriter().print(request.getParameter)",
    ),
    (
        "CWE-502",
        re.compile(r"""ObjectInputStream\s*\([^)]*\)\.readObject"""),
        "STATIC-DESERIALIZATION-JAVA-OIS",
        "CRITICAL",
        "Insecure deserialization Java · ObjectInputStream.readObject",
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

        for cwe, pattern, rule_id, severity, desc in _DETECTORS:
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
        "detail": detail,
        "blocking": blocking,
        "findings_summary": by_sev,
        "top_findings": top,
    }
