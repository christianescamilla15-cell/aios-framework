"""v3.6.5 · Helpers compartidos para wraps de scanners externos.

Todos los wraps (npm-audit v3.6.4 · semgrep · trivy · checkov · sbom)
siguen el mismo patrón:

1. Verificar que la CLI externa exista (`check_cli_available`)
2. Ejecutar con subprocess + timeout (`run_cli_capture`)
3. Parsear output (JSON típicamente) a dataclass Finding-like
4. Aplicar gate con --fail-on threshold
5. Format human / JSON consistente

Este módulo extrae los pasos 1 y 2 · además del severity ordering común.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# Severity ordering común · usado por todos los gate thresholds
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class CliResult:
    """Resultado de invocar una CLI externa."""
    available: bool
    returncode: int
    stdout: str
    stderr: str
    error: Optional[str] = None


def check_cli_available(cmd_name: str) -> bool:
    """True si `cmd_name` está en PATH."""
    return shutil.which(cmd_name) is not None


def run_cli_capture(cmd: list[str], cwd: Optional[Path] = None,
                    timeout_seconds: int = 300,
                    accept_nonzero_exits: set[int] | None = None) -> CliResult:
    """Ejecuta `cmd` capturando stdout/stderr.

    `accept_nonzero_exits` · set de exit codes que NO se tratan como error
    real (útil para tools que retornan != 0 cuando encuentran findings ·
    ej. npm audit retorna 1 con vulns · no es error).

    Si la CLI no existe (cmd[0] not in PATH) · retorna available=False
    con error descriptivo · NO lanza excepción.
    """
    if not cmd:
        return CliResult(available=False, returncode=-1, stdout="", stderr="",
                         error="empty command")

    if not check_cli_available(cmd[0]):
        return CliResult(available=False, returncode=-1, stdout="", stderr="",
                         error=f"{cmd[0]} CLI no encontrado en PATH")

    try:
        result = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True,
            timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired:
        return CliResult(available=True, returncode=-1, stdout="", stderr="",
                         error=f"{cmd[0]} timeout ({timeout_seconds}s)")
    except OSError as e:
        return CliResult(available=True, returncode=-1, stdout="", stderr="",
                         error=f"subprocess error: {e}")

    accepted = accept_nonzero_exits or set()
    # Aceptar exits que el tool usa como "info" (p.ej. findings found)
    if result.returncode != 0 and result.returncode not in accepted:
        # Igual retornamos stdout si hay data · caller decide
        return CliResult(available=True, returncode=result.returncode,
                         stdout=result.stdout or "", stderr=result.stderr or "",
                         error=f"{cmd[0]} exit {result.returncode}")

    return CliResult(available=True, returncode=result.returncode,
                     stdout=result.stdout or "", stderr=result.stderr or "",
                     error=None)


def meets_threshold(severity: str,
                    fail_on_severity: Optional[str]) -> bool:
    """True si `severity` es >= `fail_on_severity` en el orden común."""
    if not fail_on_severity:
        return False
    current = SEVERITY_ORDER.get(severity.upper(), 0)
    threshold = SEVERITY_ORDER.get(fail_on_severity.upper(), 0)
    return current >= threshold and threshold > 0
