"""Helpers compartidos · generación docs Discovery (v3.7.0).

Funciones utilitarias reutilizables por los 7 subcomandos discovery-*.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from aios.core.plan_v5 import APPS, AppMetadata


def resolve_app(app_key: str) -> AppMetadata:
    """Valida + retorna metadata de app. Lanza ValueError si no existe."""
    key = app_key.lower().strip()
    if key not in APPS:
        raise ValueError(
            f"Aplicativo '{app_key}' no encontrado. "
            f"Opciones: {', '.join(sorted(APPS.keys()))}"
        )
    return APPS[key]


def default_output_dir(root: Path) -> Path:
    """Directorio de salida default: <root>/analisis/fase-1-discovery/."""
    return root / "analisis" / "fase-1-discovery"


def ensure_output_dir(out_dir: Path) -> Path:
    """Crea directorio si no existe."""
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def yaml_frontmatter(title: str, description: str, doc_type: str,
                     app: AppMetadata, version: str = "1.0") -> str:
    """Genera frontmatter YAML estándar para docs Discovery."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return (
        "---\n"
        f"title: {title}\n"
        f"app: {app.short}\n"
        f"app_long_name: {app.long_name}\n"
        f"tier: {app.tier}\n"
        f"criticality: {app.criticality}\n"
        f"doc_type: {doc_type}\n"
        f"version: {version}\n"
        f"generated_at: {now}\n"
        f"generated_by: AIOS v3.7.0 · discovery module\n"
        f"description: {description}\n"
        "---\n\n"
    )


def section_header(emoji: str, title: str, level: int = 2) -> str:
    """Header markdown con emoji + título (h2 default)."""
    return f"\n{'#' * level} {emoji} {title}\n\n"


def write_doc(path: Path, content: str) -> Path:
    """Escribe doc · crea parent dirs · retorna path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def humanize_stack(stack: str) -> str:
    """Limpia string stack para display markdown."""
    return stack.replace(" · ", " \\| ") if " · " in stack else stack
