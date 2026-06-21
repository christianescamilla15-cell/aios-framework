"""AIOS MCP server · expone Mythos/Nemesis/Arena como tools MCP para
consumir desde Claude Code u otros clientes MCP-compatibles.

Launch:
    aios-mcp              # stdio transport · default · para Claude Code
    aios-mcp --http 8765  # opcional · HTTP transport para testing

Config en Claude Code (~/.claude.json o user settings):
    {
      "mcpServers": {
        "aios": { "command": "aios-mcp", "args": [] }
      }
    }

Tools expuestos:
- `security_scan(project_path)` · corre el embedded scanner (34
  detectores · 5 lenguajes) y retorna findings dict.
- `release_gate_check(project_path)` · corre aios release completo.
- `arena_run(target, max_rounds, target_url?)` · invoca arena CLI
  via subprocess · retorna verdict.
- `arena_list_targets()` · lista TUTs.
- `engagement_scaffold(app_id, quarter?)` · invoca scaffold.py.
- `engagement_list()` · lista catalogo 10 apps ACME.
- `aggregate_report(project_path)` · retorna markdown consolidado.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional

from mcp.server.fastmcp import FastMCP

from .core.arena_runner import list_targets as _arena_list_targets
from .core.arena_runner import run_arena as _run_arena
from .core.engagement_scaffold import run_scaffold as _run_scaffold
from .core.release_gate import check_release_readiness
from .core.report_aggregator import build_report
from .core.security_gate import scan_directory, run_security_gate


app = FastMCP("aios")


def _kcb_emit(
    event_type: str,
    payload: dict,
    duration_ms: Optional[int] = None,
    correlation_id: Optional[str] = None,
) -> None:
    """Emit event to kcb events.jsonl · no-op if KCB_SESSION_ID unset.
    Never raises · instrumentation failures must not break the tool."""
    session_id = os.environ.get("KCB_SESSION_ID")
    if not session_id:
        return
    try:
        state_dir = Path(os.environ.get("KCB_STATE_DIR", ".kcb-state")).expanduser()
        events_path = state_dir / "events.jsonl"
        event: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "session_id": session_id,
            "event_type": event_type,
            "actor": os.environ.get("KCB_ACTOR", "aios-mcp"),
            "payload": payload,
        }
        if duration_ms is not None:
            event["duration_ms"] = duration_ms
        if correlation_id:
            event["correlation_id"] = correlation_id
        events_path.parent.mkdir(parents=True, exist_ok=True)
        with events_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        pass


def instrument_tool(func: Callable) -> Callable:
    """Decorator · emit mcp_tool_call start/end events to the kcb bridge.
    Args are sanitized to str and truncated to 200 chars. No-op when
    KCB_SESSION_ID is unset. Errors never leak from instrumentation."""
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        tool_name = func.__name__
        correlation_id = f"mcp-{tool_name}-{int(time.time() * 1000)}"
        sanitized: dict[str, Any] = {}
        for i, a in enumerate(args):
            sanitized[f"arg{i}"] = str(a)[:200]
        for k, v in kwargs.items():
            sanitized[k] = str(v)[:200]
        _kcb_emit(
            "mcp_tool_call",
            {"tool": tool_name, "phase": "start", "args": sanitized},
            correlation_id=correlation_id,
        )
        start = time.perf_counter()
        error_msg: Optional[str] = None
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            error_msg = f"{type(exc).__name__}: {exc}"[:300]
            raise
        finally:
            duration_ms = int((time.perf_counter() - start) * 1000)
            payload: dict[str, Any] = {"tool": tool_name, "phase": "end"}
            if error_msg:
                payload["error"] = error_msg
            _kcb_emit(
                "mcp_tool_call",
                payload,
                duration_ms=duration_ms,
                correlation_id=correlation_id,
            )
    return wrapper


@app.tool()
@instrument_tool
def security_scan(project_path: str) -> dict:
    """Corre el embedded security scanner (34 detectores · 9 CWEs) sobre
    un path local y retorna resumen con summary + top findings."""
    root = Path(project_path).expanduser().resolve()
    if not root.exists():
        return {"error": f"path no existe: {root}"}
    findings = scan_directory(root)
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    top = [
        {
            "cwe": f.cwe, "severity": f.severity, "rule_id": f.rule_id,
            "file": f.file, "line": f.line,
        }
        for f in sorted(
            findings,
            key=lambda x: (x.severity != "CRITICAL", x.severity != "HIGH"),
        )[:10]
    ]
    return {
        "path": str(root),
        "total_findings": len(findings),
        "by_severity": by_sev,
        "top_findings": top,
    }


@app.tool()
@instrument_tool
def release_gate_check(project_path: str) -> dict:
    """Ejecuta el release gate completo (7 checks · incluye security
    static scan). Util para queries tipo 'puedo desplegar?'."""
    root = Path(project_path).expanduser().resolve()
    if not root.exists():
        return {"error": f"path no existe: {root}"}
    try:
        return check_release_readiness(root)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


@app.tool()
@instrument_tool
def arena_list_targets() -> dict:
    """Lista los TUTs (Target-Under-Test) disponibles para Arena
    self-play. Requiere `arena` CLI en PATH."""
    targets = _arena_list_targets()
    return {"count": len(targets), "targets": targets}


@app.tool()
@instrument_tool
def arena_run(
    target: str,
    max_rounds: int = 10,
    target_url: Optional[str] = None,
    timeout_seconds: int = 1200,
) -> dict:
    """Ejecuta Arena self-play (Mythos vs Nemesis) contra un TUT.
    Retorna verdict + metadata + path al timeline. Si target_url
    esta seteado, activa NucleiExploitRunner contra HTTP vivo."""
    result = _run_arena(
        target=target,
        target_url=target_url,
        max_rounds=max_rounds,
        timeout_seconds=timeout_seconds,
    )
    return {
        "ok": result.ok,
        "verdict": result.verdict,
        "rounds_completed": result.rounds_completed,
        "mythos_win_streak": result.mythos_win_streak,
        "stalemate_counter": result.stalemate_counter,
        "run_id": result.run_id,
        "timeline_path": result.timeline_path,
        "elapsed_seconds": result.elapsed_seconds,
        "detail": result.detail[:400],
    }


@app.tool()
@instrument_tool
def engagement_list(project_root: str = ".") -> dict:
    """Lista el catalogo de apps para Nemesis engagement scaffolds.
    Requiere `engagement.scaffold_script` en aios-config.json."""
    root = Path(project_root).expanduser().resolve()
    result = _run_scaffold(root, ["--list"], timeout=30)
    return {
        "ok": result.ok,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
    }


@app.tool()
@instrument_tool
def engagement_scaffold(
    app_id: str,
    project_root: str = ".",
    quarter: Optional[str] = None,
    force: bool = False,
    dry_run: bool = False,
) -> dict:
    """Genera el paquete de engagement (roe.yaml + BRIEFING + PREFLIGHT
    + RUNBOOK) para una app del catalogo. Default FROZEN."""
    root = Path(project_root).expanduser().resolve()
    args = ["--app", app_id]
    if quarter:
        args.extend(["--quarter", quarter])
    if force:
        args.append("--force")
    if dry_run:
        args.append("--dry-run")
    result = _run_scaffold(root, args, timeout=60)
    return {
        "ok": result.ok,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
    }


@app.tool()
@instrument_tool
def aggregate_report(project_path: str) -> dict:
    """Genera el reporte consolidado (release + arena + SARIF +
    engagements) como markdown · no escribe a disco, retorna string."""
    root = Path(project_path).expanduser().resolve()
    if not root.exists():
        return {"error": f"path no existe: {root}"}
    report = build_report(root)
    return {
        "generated_at": report.generated_at,
        "root": report.root,
        "sections_count": len(report.sections),
        "markdown": report.to_markdown(),
    }


@app.tool()
@instrument_tool
def forbidden_literals_suggest(project_path: str = ".") -> dict:
    """Devuelve guia + estado del config de forbidden_literals que
    security_scan consume desde aios-config.json.

    Verifica si `aios-config.json` existe en project_path y reporta
    el count actual. Retorna categorias de ejemplo con placeholders
    (patrones genericos · no valores sensibles) y un JSON template
    listo para copy-paste al config."""
    root = Path(project_path).expanduser().resolve()
    cfg_file = root / "aios-config.json"
    current_count = 0
    current_enabled = False
    config_status = "missing"
    if cfg_file.exists():
        config_status = "present"
        try:
            raw = json.loads(cfg_file.read_text(encoding="utf-8"))
            sg = raw.get("security_gate", {}) if isinstance(raw, dict) else {}
            current_enabled = bool(sg.get("enabled", False))
            current_count = len(
                [lit for lit in sg.get("forbidden_literals", []) if lit]
            )
        except Exception as exc:  # noqa: BLE001
            config_status = f"invalid_json: {exc}"

    example_categories = [
        {
            "category": "hardcoded_credentials",
            "description": "passwords, API keys, secret tokens inline en codigo",
            "placeholders": [
                "<HARDCODED_PASSWORD>",
                "<API_KEY_LITERAL>",
                "<BEARER_TOKEN>",
            ],
        },
        {
            "category": "internal_ip_addresses",
            "description": "IPs de red interna que no deben salir del perimetro",
            "placeholders": [
                "<INTERNAL_IP_PROD>",
                "<INTERNAL_IP_STAGE>",
                "<DB_HOST_LITERAL>",
            ],
        },
        {
            "category": "domain_specific_ids",
            "description": "IDs de negocio que no deben quedar hardcoded",
            "placeholders": [
                "<FIXTURE_RECORD_ID>",
                "<TEST_TRANSACTION_CODE>",
                "<LEGACY_SERVICE_ID>",
            ],
        },
        {
            "category": "project_branding",
            "description": "nombres codigo o branding que no debe filtrarse",
            "placeholders": [
                "<INTERNAL_PROJECT_CODENAME>",
                "<LEGACY_SYSTEM_NAME>",
            ],
        },
    ]

    template = {
        "security_gate": {
            "enabled": True,
            "strict": False,
            "max_critical": 0,
            "max_high": 5,
            "forbidden_literals": [
                "<REPLACE_WITH_YOUR_LITERAL_1>",
                "<REPLACE_WITH_YOUR_LITERAL_2>",
            ],
        }
    }

    return {
        "config_path": str(cfg_file),
        "config_status": config_status,
        "security_gate_enabled": current_enabled,
        "current_forbidden_literals_count": current_count,
        "how_to_configure": (
            "Agrega tus literales en aios-config.json -> "
            "security_gate.forbidden_literals (lista de strings). "
            "Despues corre security_scan o release_gate_check para que "
            "los detecte. Este tool NO expone los literales en si · "
            "se cargan desde el config del proyecto."
        ),
        "example_categories": example_categories,
        "config_template": template,
        "canonical_amx_catalog_hint": (
            "El catalogo ACME canonico esta versionado en el repo privado "
            "acme-hallazgos-audit (06_amx_policy.md + policy.py). Usarlo "
            "como fuente de verdad para proyectos ACME · copiar al "
            "aios-config.json local del proyecto auditado."
        ),
    }


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="AIOS MCP server")
    parser.add_argument(
        "--http", type=int, default=None,
        help="Si se pasa un puerto, sirve MCP sobre HTTP (default: stdio)",
    )
    args = parser.parse_args(argv)

    if args.http:
        app.run(transport="sse", host="127.0.0.1", port=args.http)
    else:
        app.run(transport="stdio")


if __name__ == "__main__":
    main()
