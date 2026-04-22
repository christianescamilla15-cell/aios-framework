"""Memory Engine — persistent project context management."""
from __future__ import annotations

from pathlib import Path
from typing import Dict


MEMORY_DEFAULTS: Dict[str, str] = {
    "product_context.md": "# Product Context\n\nDescribe the product, users, and critical workflows.\n",
    "tech_context.md": "# Tech Context\n\nDescribe the stack, tooling, and infrastructure.\n",
    "architecture_context.md": "# Architecture Context\n\nDescribe modules, services, and dependencies.\n",
    "active_workstream.md": "# Active Workstream\n\nNo active workstream yet.\n",
    "recent_decisions.md": "# Recent Decisions\n\n",
    "known_risks.md": "# Known Risks\n\n",
}


def ensure_memory(root: Path) -> int:
    """Create memory directory and default files. Returns count of new files created."""
    memory_dir = root / "ai-memory"
    memory_dir.mkdir(parents=True, exist_ok=True)
    created = 0
    for name, content in MEMORY_DEFAULTS.items():
        path = memory_dir / name
        if not path.exists():
            path.write_text(content, encoding="utf-8")
            created += 1
    return created


def read_memory(root: Path) -> Dict[str, str]:
    """Read all memory files into a dict."""
    memory_dir = root / "ai-memory"
    result = {}
    if memory_dir.exists():
        for f in memory_dir.glob("*.md"):
            result[f.name] = f.read_text(encoding="utf-8")
    return result


def update_workstream(root: Path, task: str, mode: str, spec_path: str, phase: str = "Context Discovery", summary: str = "", next_step: str = "") -> None:
    """Update active workstream."""
    content = f"""# Active Workstream

## Current Task
{task}

## Mode
{mode}

## Active Spec
{spec_path}

## Current Phase
{phase}

## Session Summary
{summary}

## Next Step
{next_step or "Fill spec files, then run execution prompt."}
"""
    # v1.7.3 · auto-crear ai-memory dir si no existe
    memory_dir = root / "ai-memory"
    memory_dir.mkdir(parents=True, exist_ok=True)
    (memory_dir / "active_workstream.md").write_text(content, encoding="utf-8")


def append_decision(root: Path, entry: str) -> None:
    """Append to recent_decisions.md."""
    path = root / "ai-memory" / "recent_decisions.md"
    existing = path.read_text(encoding="utf-8") if path.exists() else "# Recent Decisions\n\n"
    path.write_text(existing + f"\n{entry}\n", encoding="utf-8")


def append_risk(root: Path, entry: str) -> None:
    """Append to known_risks.md."""
    path = root / "ai-memory" / "known_risks.md"
    existing = path.read_text(encoding="utf-8") if path.exists() else "# Known Risks\n\n"
    path.write_text(existing + f"\n{entry}\n", encoding="utf-8")


def get_active_task(root: Path) -> Dict[str, str]:
    """Parse active workstream and return current state."""
    path = root / "ai-memory" / "active_workstream.md"
    if not path.exists():
        return {"task": "", "mode": "", "spec": "", "phase": ""}

    content = path.read_text(encoding="utf-8")
    result = {}
    lines = content.splitlines()
    for i, line in enumerate(lines):
        s = line.strip()
        if s == "## Current Task" and i + 1 < len(lines):
            result["task"] = lines[i + 1].strip()
        elif s == "## Mode" and i + 1 < len(lines):
            result["mode"] = lines[i + 1].strip()
        elif s == "## Active Spec" and i + 1 < len(lines):
            result["spec"] = lines[i + 1].strip()
        elif s == "## Current Phase" and i + 1 < len(lines):
            result["phase"] = lines[i + 1].strip()
    return result


# ---------------------------------------------------------------------------
# v1.7.3 · Checkpoint (BUG-003 · resumption automatica entre fases)
# ---------------------------------------------------------------------------
#
# Objetivo: cuando Kiro hit el limite de contexto mid-fase (o el usuario
# dice "continua"), el agente lee este checkpoint y retoma desde el ultimo
# sub-step validado · sin re-procesar el workspace completo ni perder
# progreso intermedio.
#
# Formato en active_workstream.md:
#     ## Checkpoint
#     phase_completed: FASE 2
#     phase_in_progress: FASE 3 · step 2/6 · shared/ libraries
#     next_action: crea shared/secrets/ISecretsProvider por stack
#     last_commit: 6ff65d4
#     updated: 2026-04-22T16:57:08Z


def get_checkpoint(root: Path) -> Dict[str, str]:
    """v1.7.3 · lee el checkpoint de resumption del active_workstream.md.

    Retorna dict con keys: phase_completed · phase_in_progress ·
    next_action · last_commit · updated. Vacios si no existe checkpoint.
    """
    path = root / "ai-memory" / "active_workstream.md"
    if not path.exists():
        return {
            "phase_completed": "", "phase_in_progress": "",
            "next_action": "", "last_commit": "", "updated": "",
        }
    content = path.read_text(encoding="utf-8")
    result = {
        "phase_completed": "", "phase_in_progress": "",
        "next_action": "", "last_commit": "", "updated": "",
    }
    # Parseo simple del bloque "## Checkpoint · key: value" lines
    in_checkpoint = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("## Checkpoint"):
            in_checkpoint = True
            continue
        if in_checkpoint and stripped.startswith("## "):
            # Siguiente section · fin del bloque checkpoint
            break
        if in_checkpoint and ":" in stripped:
            key, _, val = stripped.partition(":")
            key_norm = key.strip().lower().replace(" ", "_").replace("-", "_")
            if key_norm in result:
                result[key_norm] = val.strip()
    return result


def update_checkpoint(
    root: Path,
    phase_completed: str = "",
    phase_in_progress: str = "",
    next_action: str = "",
    last_commit: str = "",
) -> None:
    """v1.7.3 · escribe/actualiza el bloque ## Checkpoint del
    active_workstream.md. Preserva las otras secciones intactas.

    Diseñado para ser llamado despues de cada build-gate PASS o al
    cerrar un sub-step atomic · permite que 'aios resume' retome
    exactamente donde quedo.
    """
    from datetime import datetime, timezone
    memory_dir = root / "ai-memory"
    memory_dir.mkdir(parents=True, exist_ok=True)
    path = memory_dir / "active_workstream.md"

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Leer contenido actual o bootstrap
    if path.exists():
        content = path.read_text(encoding="utf-8")
    else:
        content = "# Active Workstream\n\nNo active workstream yet.\n"

    # Reemplazar o agregar el bloque ## Checkpoint
    new_block = (
        "## Checkpoint\n"
        f"phase_completed: {phase_completed}\n"
        f"phase_in_progress: {phase_in_progress}\n"
        f"next_action: {next_action}\n"
        f"last_commit: {last_commit}\n"
        f"updated: {now}\n"
    )

    lines = content.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    replaced = False
    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("## Checkpoint"):
            # Skip hasta la siguiente ## section
            out.append(new_block)
            replaced = True
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("## "):
                i += 1
            continue
        out.append(line)
        i += 1

    if not replaced:
        # Append al final
        if out and not out[-1].endswith("\n"):
            out[-1] = out[-1] + "\n"
        out.append("\n" + new_block)

    path.write_text("".join(out), encoding="utf-8")


def resume_instruction(root: Path) -> str:
    """v1.7.3 · genera la instruccion human-readable para retomar la
    sesion · util cuando el usuario escribe 'aios resume' o 'continua'.

    Formato one-liner para que Kiro lo vea en 1 turn sin re-procesar
    todo el workspace.
    """
    cp = get_checkpoint(root)
    if not any(cp.values()):
        return "(sin checkpoint · workstream nuevo · empieza FASE 0)"
    parts = []
    if cp.get("phase_completed"):
        parts.append(f"ultima fase completada: {cp['phase_completed']}")
    if cp.get("phase_in_progress"):
        parts.append(f"en progreso: {cp['phase_in_progress']}")
    if cp.get("next_action"):
        parts.append(f"next: {cp['next_action']}")
    if cp.get("last_commit"):
        parts.append(f"last_commit: {cp['last_commit']}")
    if cp.get("updated"):
        parts.append(f"updated: {cp['updated']}")
    return " · ".join(parts)
