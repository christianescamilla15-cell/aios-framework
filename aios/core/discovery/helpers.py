"""Helpers compartidos · generación docs Discovery (v3.7.0).

Funciones utilitarias reutilizables por los 7 subcomandos discovery-*.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

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


# ───────── PDF helpers (v3.7.1 · reutilizable entre subcomandos) ──────

def minimal_md_to_html(md: str, title: str) -> str:
    """Conversión minimalista MD → HTML con CSS ACME-style para PDF weasyprint.

    Soporta: headers H1-H3 · bold · italic · code inline · listas · tablas
    pipe-separated · blockquotes · hr. Suficiente para docs Discovery.
    """
    import re
    body = md.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    body = re.sub(r"`([^`]+)`", r"<code>\1</code>", body)
    body = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", body)
    body = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<em>\1</em>", body)
    body = re.sub(r"^# (.+)$", r"<h1>\1</h1>", body, flags=re.M)
    body = re.sub(r"^## (.+)$", r"<h2>\1</h2>", body, flags=re.M)
    body = re.sub(r"^### (.+)$", r"<h3>\1</h3>", body, flags=re.M)

    lines = body.split("\n")
    out = []
    in_table = False
    for ln in lines:
        if re.match(r"^\s*\|.*\|\s*$", ln):
            if re.match(r"^\s*\|[\s\-|:]+\|\s*$", ln):
                continue
            cells = [c.strip() for c in ln.strip().strip("|").split("|")]
            if not in_table:
                out.append("<table>")
                out.append("<tr>" + "".join(f"<th>{c}</th>" for c in cells) + "</tr>")
                in_table = True
            else:
                out.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
        else:
            if in_table:
                out.append("</table>")
                in_table = False
            if re.match(r"^\s*[-*]\s+", ln):
                out.append("<li>" + re.sub(r"^\s*[-*]\s+", "", ln) + "</li>")
            elif re.match(r"^\s*&gt;\s+", ln):
                out.append("<blockquote>" + re.sub(r"^\s*&gt;\s+", "", ln) + "</blockquote>")
            elif ln.strip() == "---":
                out.append("<hr>")
            elif ln.strip() == "":
                out.append("<br>")
            else:
                out.append(f"<p>{ln}</p>")
    if in_table:
        out.append("</table>")

    css = (
        '@page { size: Letter; margin: 2cm; '
        '@bottom-right { content: "p. " counter(page) "/" counter(pages); '
        'font-size: 8pt; color: #6b7280; } }'
        'body { font-family: -apple-system, "Segoe UI", Arial; '
        'color: #1f2937; font-size: 9.8pt; line-height: 1.42; }'
        'h1 { font-size: 17pt; color: #0a2540; '
        'border-bottom: 3px solid #0a2540; padding-bottom: 6px; }'
        'h2 { font-size: 12pt; color: #0a2540; '
        'border-left: 4px solid #0a2540; padding-left: 8px; margin-top: 18px; '
        'page-break-after: avoid; }'
        'h3 { font-size: 10.5pt; color: #334155; margin-top: 14px; '
        'page-break-after: avoid; }'
        'table { width: 100%; border-collapse: collapse; '
        'margin: 6px 0 10px 0; font-size: 8.5pt; }'
        'th { background: #0a2540; color: #fff; text-align: left; '
        'padding: 5px 7px; }'
        'td { padding: 4px 7px; border-bottom: 1px solid #e5e7eb; '
        'vertical-align: top; }'
        'tr:nth-child(even) td { background: #f9fafb; }'
        'code { font-family: Consolas, monospace; font-size: 8.4pt; '
        'background: #f3f4f6; padding: 1px 4px; border-radius: 3px; }'
        'li { margin-bottom: 3px; }'
        'blockquote { background: #fffbeb; border-left: 4px solid #f59e0b; '
        'padding: 8px 12px; margin: 8px 0; }'
        'hr { border: none; border-top: 1px solid #e5e7eb; margin: 12px 0; }'
    )
    return (
        '<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">'
        f'<title>{title}</title><style>{css}</style></head><body>'
        + "\n".join(out)
        + "</body></html>"
    )


def md_to_pdf(md_path: Path, pdf_path: Path, timeout: int = 60) -> bool:
    """Convierte un MD existente a PDF usando weasyprint (subprocess).

    Retorna True si el PDF fue generado · False si weasyprint no está
    instalado o falló. Nunca lanza excepción (caller decide reportar).
    """
    import os
    import subprocess
    import tempfile

    if not md_path.exists():
        return False

    md_content = md_path.read_text(encoding="utf-8")
    html_content = minimal_md_to_html(md_content, md_path.stem)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(html_content)
        tmp_name = tmp.name
    try:
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(
                ["weasyprint", tmp_name, str(pdf_path)],
                capture_output=True, timeout=timeout, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        return pdf_path.exists()
    finally:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
