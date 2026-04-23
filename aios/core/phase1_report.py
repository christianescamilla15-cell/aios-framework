"""v3.5.1 · Phase 1 Discovery Report Generator.

Genera el Discovery Package consolidado del plan v5 para un aplicativo. Lee los
9 entregables estándar de `<root>/analisis/fase-1-discovery/` · los enriquece
con metadata del plan v5 (Tier · go-live · bloqueantes cross-app · patrones
obligatorios) · produce un markdown maestro y opcional PDF.

Uso:
    aios phase1-report --app sicofav --root <app_root>
    aios phase1-report --app sicofav --root <app_root> --pdf
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from aios.core.plan_v5 import (
    APPS, PHASE1_DELIVERABLES, TIER_PATTERNS,
    CROSS_APP_BLOCKERS, get_app, patterns_for_tier,
)


def find_discovery_dir(root: Path) -> Path | None:
    """Localiza `fase-1-discovery/` dentro del root."""
    candidates = [
        root / "analisis" / "fase-1-discovery",
        root / "fase-1-discovery",
        root / "docs" / "fase-1-discovery",
    ]
    for c in candidates:
        if c.exists() and c.is_dir():
            return c
    return None


def read_deliverable(disc_dir: Path, filename: str) -> Dict[str, str]:
    """Lee un entregable Fase 1 · retorna dict con metadata y contenido."""
    path = disc_dir / filename
    if not path.exists():
        return {"exists": False, "path": str(path), "content": "", "summary": ""}
    content = path.read_text(encoding="utf-8", errors="ignore")
    # Extraer el summary del frontmatter YAML si existe
    summary = ""
    if content.startswith("---"):
        end = content.find("---", 3)
        if end > 0:
            fm = content[3:end]
            for line in fm.splitlines():
                if line.strip().startswith("description:"):
                    summary = line.split(":", 1)[1].strip()
                    break
    return {
        "exists": True,
        "path": str(path),
        "content": content,
        "summary": summary,
        "lines": content.count("\n"),
    }


def build_discovery_package(app_key: str, root: Path) -> str:
    """Construye el markdown del Discovery Package maestro."""
    app = get_app(app_key)
    if app is None:
        raise ValueError(
            f"Aplicativo '{app_key}' no encontrado en plan v5. "
            f"Opciones: {', '.join(APPS.keys())}"
        )

    disc_dir = find_discovery_dir(root)
    if disc_dir is None:
        raise FileNotFoundError(
            f"No se encontró 'fase-1-discovery/' en {root}. "
            f"Ubicaciones buscadas: analisis/fase-1-discovery · fase-1-discovery · docs/fase-1-discovery"
        )

    patterns = patterns_for_tier(app.tier)
    deliverables = [read_deliverable(disc_dir, d["file"]) for d in PHASE1_DELIVERABLES]

    md: List[str] = []
    md.append(f"# {app.short} · Fase 1 Discovery Package · Plan v5")
    md.append("")
    md.append(f"**Aplicativo #{app.app_id} · Tier {app.tier} · {app.criticality}**")
    md.append(f"**{app.long_name}**")
    md.append("")
    md.append(f"- **Go-live objetivo:** {app.go_live}")
    md.append(f"- **Arranque Fase 1:** {app.arranque_fase1}")
    md.append(f"- **Duración estimada:** {app.duracion_weeks} semanas")
    md.append(f"- **Stack AS-IS:** {app.stack_as_is}")
    md.append(f"- **Owner funcional:** {app.owner_funcional}")
    md.append(f"- **Owner técnico:** {app.owner_tecnico}")
    md.append(f"- **Código disponible:** {'✅ Sí' if app.codigo_disponible else '⚠ No'}")
    if app.notas:
        md.append(f"- **Notas:** {app.notas}")
    md.append("")
    md.append("---")
    md.append("")

    # Índice de entregables
    md.append("## 📋 Índice de entregables Fase 1")
    md.append("")
    md.append("| # | Entregable | Fuente | Status | Resumen |")
    md.append("|---|---|---|---|---|")
    for d_meta, d_data in zip(PHASE1_DELIVERABLES, deliverables):
        status = "✅ presente" if d_data["exists"] else "⚠ ausente"
        summary = d_data.get("summary", "")[:120] if d_data["exists"] else "—"
        md.append(
            f"| {d_meta['num']} | {d_meta['title']} | `{d_meta['file']}` | {status} | {summary} |"
        )
    md.append("")
    md.append("---")
    md.append("")

    # Patrones obligatorios Tier
    md.append(f"## 🏗 Patrones obligatorios Tier {app.tier} (plan v5)")
    md.append("")
    for key, items in patterns.items():
        md.append(f"### {key.replace('_', ' ').title()}")
        md.append("")
        for item in items:
            md.append(f"- {item}")
        md.append("")

    # Bloqueantes cross-app
    md.append("## 🔴 Bloqueantes cross-app (plan v5)")
    md.append("")
    md.append("| ID | Título | Impacta | Owner | Deadline | Status |")
    md.append("|---|---|---|---|---|---|")
    for b in CROSS_APP_BLOCKERS:
        md.append(
            f"| {b.blocker_id} | {b.title} | {b.impact} | {b.owner} | {b.deadline} | {b.status} |"
        )
    md.append("")
    md.append("---")
    md.append("")

    # Resúmenes de cada entregable
    md.append("## 📖 Entregables Fase 1 · resúmenes")
    md.append("")
    for d_meta, d_data in zip(PHASE1_DELIVERABLES, deliverables):
        md.append(f"### {d_meta['num']} · {d_meta['title']}")
        md.append("")
        md.append(f"**Archivo:** `fase-1-discovery/{d_meta['file']}` · **{d_meta['desc']}**")
        md.append("")
        if not d_data["exists"]:
            md.append("> ⚠ **Entregable no encontrado** · generar antes de cerrar Fase 1.")
            md.append("")
            continue
        md.append(f"- Líneas: {d_data['lines']}")
        if d_data["summary"]:
            md.append(f"- Summary: {d_data['summary']}")
        md.append("")

    md.append("---")
    md.append("")

    # Honestidad metodológica (plan v5)
    md.append("## ⚖ Honestidad metodológica (plan v5)")
    md.append("")
    md.append("Tres claims que este Discovery Package **NO** hace:")
    md.append("")
    if app.tier == "T0":
        md.append("- **T0 NO admite 99.99% prometido** · AIOS cubre 53-65% · el resto es humanos")
    md.append("- **Código correcto ≠ Production-Ready** · solo Ready for QA")
    md.append("- **AIOS es pre-gate, no reemplazo** · Veracode · Tenable · WIZ · Prisma")
    md.append("  obligatorios al cierre Fase 4 con firma Miguel Rachid")
    md.append("")

    # Gates AMX aplicables (plan v5 §3.5)
    md.append("## ✅ Gates AMX aplicables al cierre Fase 1")
    md.append("")
    md.append("Según plan v5 §3.5:")
    md.append("")
    md.append("- Alta del proyecto en óptimo")
    md.append("- Acceso formal al código")
    md.append("- Evidencia del workshop técnico realizado")
    md.append("- Firma del Discovery Package por owners")
    md.append("")
    md.append("---")
    md.append("")

    # Footer
    md.append(f"**Generado por:** `aios phase1-report --app {app_key}` · AIOS v3.5.1")
    md.append(f"**Plan autoritativo:** `Justificacion_Plan_v5_23abr.md`")
    md.append(f"**Fuentes:** {disc_dir}")

    return "\n".join(md)


def write_package(app_key: str, root: Path, output: Path | None = None) -> Path:
    """Escribe el Discovery Package a disco · retorna path del archivo."""
    md = build_discovery_package(app_key, root)
    if output is None:
        app = get_app(app_key)
        short = app.short if app else app_key.upper()
        output = root / "analisis" / f"{short}_FASE1_DISCOVERY_PACKAGE.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(md, encoding="utf-8")
    return output
