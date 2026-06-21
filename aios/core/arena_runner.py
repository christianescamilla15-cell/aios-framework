"""Arena self-play runner · invoca el CLI de Arena bajo demanda.

Separado del release gate porque Arena self-play es lento (minutos
por 10 rounds) · no apto para integrar en `aios release`. Se expone
como subcomando `aios arena` para uso on-demand:

  aios arena --target acme-mini-refund [--target-url http://localhost:8888]

Si el binario `arena` no esta en PATH, emite mensaje con instrucciones
de instalacion (no invoca fallback embedded · Arena requiere mythos +
nemesis instalados, no vale la pena duplicar eso).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ArenaResult:
    ok: bool
    verdict: Optional[str] = None
    rounds_completed: int = 0
    mythos_win_streak: int = 0
    stalemate_counter: int = 0
    run_id: Optional[str] = None
    timeline_path: Optional[str] = None
    detail: str = ""
    elapsed_seconds: float = 0.0


def _find_arena_cli() -> Optional[str]:
    return shutil.which("arena")


def _parse_stdout(stdout: str) -> dict:
    """Parse el output del CLI de Arena (verdict · rounds · timeline)."""
    out: dict = {}
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("Verdict:"):
            out["verdict"] = line.split(":", 1)[1].strip()
        elif line.startswith("Rounds completed:"):
            try:
                out["rounds_completed"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("Mythos win streak:"):
            try:
                out["mythos_win_streak"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("Stalemate counter:"):
            try:
                out["stalemate_counter"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif "arena-memory/runs/" in line:
            out["timeline_path"] = line
            if "/arena-" in line:
                try:
                    out["run_id"] = line.split("arena-")[-1].split("/")[0]
                    out["run_id"] = f"arena-{out['run_id']}"
                except Exception:
                    pass
    return out


def run_arena(
    target: str,
    target_url: Optional[str] = None,
    max_rounds: int = 10,
    timeout_seconds: int = 1200,
) -> ArenaResult:
    """Invoca `arena run <target> [--target-url ...] --max-rounds N`.

    Retorna ArenaResult estructurado. No hace teardown del container
    si el usuario uso --target-url (responsabilidad del caller).
    """
    import time

    cli = _find_arena_cli()
    if cli is None:
        return ArenaResult(
            ok=False,
            detail=(
                "arena CLI no encontrado en PATH · instalar desde "
                "acme-hallazgos-audit/arena: `pip install -e arena/`"
            ),
        )

    cmd = [cli, "run", target, "--max-rounds", str(max_rounds)]
    if target_url:
        cmd.extend(["--target-url", target_url])

    started = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ArenaResult(
            ok=False,
            detail=f"arena timeout tras {timeout_seconds}s",
            elapsed_seconds=time.monotonic() - started,
        )
    except Exception as exc:  # noqa: BLE001
        return ArenaResult(
            ok=False,
            detail=f"arena error: {exc}",
            elapsed_seconds=time.monotonic() - started,
        )

    elapsed = time.monotonic() - started
    parsed = _parse_stdout(result.stdout)
    verdict = parsed.get("verdict")

    return ArenaResult(
        ok=(result.returncode == 0 and verdict is not None),
        verdict=verdict,
        rounds_completed=parsed.get("rounds_completed", 0),
        mythos_win_streak=parsed.get("mythos_win_streak", 0),
        stalemate_counter=parsed.get("stalemate_counter", 0),
        run_id=parsed.get("run_id"),
        timeline_path=parsed.get("timeline_path"),
        detail=(
            (result.stdout[-400:] or "") + "\n" + (result.stderr[-200:] or "")
        ).strip(),
        elapsed_seconds=elapsed,
    )


def write_arena_summary_to_memory(
    root: Path, result: ArenaResult, target: str, target_url: Optional[str] = None,
) -> Optional[Path]:
    """Despues de un run, escribe un resumen en ai-memory/security_findings.md.

    Esto permite que `aios status` / `aios release` tengan contexto del
    ultimo duelo sin volver a invocar Arena. El archivo es append-only:
    cada run agrega una seccion al final.
    """
    from datetime import datetime, timezone

    memory_dir = root / "ai-memory"
    if not memory_dir.exists():
        return None

    dest = memory_dir / "security_findings.md"
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    header = "# Security findings · Arena runs\n\n"
    if not dest.exists():
        dest.write_text(header, encoding="utf-8")

    status_emoji = {
        "MYTHOS_WINS": "OK", "NEMESIS_WINS": "FAIL",
        "STALEMATE": "WARN", "DRAW": "DRAW", "USER_STOPPED": "STOPPED",
    }.get(result.verdict or "", "UNKNOWN")

    section = (
        f"\n## Run {now} · {target}\n\n"
        f"- **Verdict:** `{result.verdict or 'N/A'}` [{status_emoji}]\n"
        f"- **Rounds completed:** {result.rounds_completed}\n"
        f"- **Mythos win streak:** {result.mythos_win_streak}\n"
        f"- **Stalemate counter:** {result.stalemate_counter}\n"
        f"- **Elapsed:** {result.elapsed_seconds:.1f}s\n"
        f"- **Target URL:** {target_url or '(source-only · no HTTP probe)'}\n"
        f"- **Timeline:** `{result.timeline_path or 'n/a'}`\n"
        f"- **Run ID:** `{result.run_id or 'n/a'}`\n"
    )

    with dest.open("a", encoding="utf-8") as f:
        f.write(section)
    return dest


def read_last_arena_run(root: Path) -> Optional[dict]:
    """Lee el ultimo run registrado en ai-memory/security_findings.md."""
    import re

    memory_file = root / "ai-memory" / "security_findings.md"
    if not memory_file.exists():
        return None
    content = memory_file.read_text(encoding="utf-8")
    runs = re.findall(
        r"## Run (\S+) · (\S+)\s*\n\n(.*?)(?=\n## Run |\Z)",
        content, re.DOTALL,
    )
    if not runs:
        return None
    timestamp, target, body = runs[-1]
    verdict = None
    m = re.search(r"\*\*Verdict:\*\*\s+`([^`]+)`", body)
    if m:
        verdict = m.group(1)
    return {"timestamp": timestamp, "target": target, "verdict": verdict}


def list_targets() -> list[str]:
    """Lista TUTs disponibles llamando `arena list-targets`."""
    cli = _find_arena_cli()
    if cli is None:
        return []
    try:
        result = subprocess.run(
            [cli, "list-targets"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except Exception:  # noqa: BLE001
        return []
    targets: list[str] = []
    for line in result.stdout.splitlines():
        # La tabla rich tiene separadores · heuristica simple: primera
        # columna tras `│` es el target id.
        if "│" in line:
            parts = [p.strip() for p in line.split("│") if p.strip()]
            if parts and parts[0] not in ("Target ID", ""):
                # Excluye encabezados
                if not any(c in parts[0] for c in ("━", "─", "═")):
                    targets.append(parts[0])
    return targets
