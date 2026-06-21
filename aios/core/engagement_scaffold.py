"""Engagement scaffold · wrapper para invocar el generador de Nemesis
engagements (`nemesis-engagements/_catalog/scaffold.py`) desde AIOS.

El scaffold.py vive en el repo acme-hallazgos-audit · AIOS no lo
duplica · lo localiza via config o path por defecto y lo invoca via
subprocess.

Config via aios-config.json (seccion `engagement`):
{
  "scaffold_script": "/ruta/a/nemesis-engagements/_catalog/scaffold.py",
  "quarter_default": "2026-Q2"
}

Si no esta configurado, busca en locations comunes:
- ./nemesis/nemesis-engagements/_catalog/scaffold.py
- /mnt/c/Users/eTriber/Desktop/acme-hallazgos-audit/nemesis/...
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


COMMON_LOCATIONS = [
    "nemesis/nemesis-engagements/_catalog/scaffold.py",
    "../acme-hallazgos-audit/nemesis/nemesis-engagements/_catalog/scaffold.py",
    "/mnt/c/Users/eTriber/Desktop/acme-hallazgos-audit/nemesis/nemesis-engagements/_catalog/scaffold.py",
]


@dataclass
class EngagementResult:
    ok: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0


def _load_config(root: Path) -> dict:
    cfg_file = root / "aios-config.json"
    if not cfg_file.exists():
        return {}
    try:
        data = json.loads(cfg_file.read_text(encoding="utf-8"))
        return data.get("engagement", {}) or {}
    except (json.JSONDecodeError, OSError):
        return {}


def _resolve_scaffold(root: Path) -> Optional[Path]:
    """Busca scaffold.py via config > common locations. None si no existe."""
    cfg = _load_config(root)
    from_cfg = cfg.get("scaffold_script")
    if from_cfg:
        p = Path(from_cfg)
        if p.exists():
            return p
    for rel in COMMON_LOCATIONS:
        candidate = (root / rel).resolve() if not rel.startswith("/") else Path(rel)
        if candidate.exists():
            return candidate
    return None


def _quarter_default(root: Path) -> str:
    return _load_config(root).get("quarter_default", "2026-Q2")


def run_scaffold(root: Path, args: list[str], timeout: int = 60) -> EngagementResult:
    """Ejecuta scaffold.py con los argumentos provistos.

    args · pasa argparse-style ej. ["--app", "02-arc"] o ["--list"].
    """
    script = _resolve_scaffold(root)
    if script is None:
        return EngagementResult(
            ok=False,
            stderr=(
                "scaffold.py no encontrado · configura en aios-config.json "
                "seccion `engagement.scaffold_script` con la ruta absoluta, "
                "o copia el script a ./nemesis/nemesis-engagements/_catalog/"
            ),
            exit_code=2,
        )

    cmd = [sys.executable, str(script), *args]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=script.parent,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return EngagementResult(
            ok=False, stderr=f"scaffold timeout tras {timeout}s", exit_code=124,
        )
    except Exception as exc:  # noqa: BLE001
        return EngagementResult(
            ok=False, stderr=f"scaffold error: {exc}", exit_code=1,
        )

    return EngagementResult(
        ok=(result.returncode == 0),
        stdout=result.stdout,
        stderr=result.stderr,
        exit_code=result.returncode,
    )
