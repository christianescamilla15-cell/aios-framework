"""v3.7.0 · Discovery 9 docs generator · auto-crea `fase-1-discovery/` completo.

Produce los 9 entregables estándar del plan v5 Fase 1 Discovery:

  01_code_scan.md          · output formateado de `aios scan`
  02_hallazgos_mapped.md   · findings mapeados a CWE + regulaciones
  03_arq_as_is.md          · stack + topología AS-IS desde plan_v5 + repo
  04_stakeholders.md       · owners funcional + técnico + governance
  05_vulns.md              · vulns detalle + compliance (LFPDPPP/PCI/SOX/CFF)
  06_deps.md               · dependencias + upgrade targets
  07_preguntas_nuevas.md   · template bloqueadoras + categorizadas
  08_bloqueadores.md       · cross-app + específicos del app
  09_risk_register.md      · riesgos probabilidad × impacto por tier

Uso:
    aios discovery-generate --app sicofav --root <root>
    aios discovery-generate --app sicofav --root <root> --overwrite
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any

from aios.core.plan_v5 import (
    APPS, PHASE1_DELIVERABLES, CROSS_APP_BLOCKERS,
    get_app, patterns_for_tier,
)
from aios.core.discovery.helpers import (
    ensure_output_dir, default_output_dir, resolve_app, write_doc,
    yaml_frontmatter, section_header, humanize_stack, md_to_pdf,
)


# ───────── helpers internos ─────────────────────────────────────────

def _run_scan(root: Path) -> Dict[str, Any]:
    """Ejecuta aios.scan_directory sobre root · retorna dict con stats.

    Si scan falla (ej. no hay código escaneable), retorna estructura vacía
    · el doc se genera igual con placeholder indicando no-scan-data.
    """
    try:
        from aios.core.security_gate import scan_directory
        findings = scan_directory(root)
    except Exception as exc:  # pragma: no cover · fallback resiliente
        return {"findings": [], "error": str(exc), "count": 0,
                "by_severity": {}, "by_cwe": {}}

    by_sev: Counter[str] = Counter()
    by_cwe: Counter[str] = Counter()
    for f in findings:
        sev = getattr(f, "severity", "UNKNOWN")
        by_sev[sev] += 1
        cwe = getattr(f, "cwe", "") or "N/A"
        by_cwe[cwe] += 1

    return {
        "findings": findings,
        "count": len(findings),
        "by_severity": dict(by_sev),
        "by_cwe": dict(by_cwe),
        "error": None,
    }


def _detect_stack(root: Path) -> Dict[str, List[str]]:
    """Detecta stack por patrones de archivos · retorna dict de lenguajes/frameworks."""
    patterns = {
        "dotnet": ["*.csproj", "*.sln", "*.cs"],
        "java": ["pom.xml", "build.gradle", "*.java"],
        "python": ["requirements.txt", "pyproject.toml", "*.py"],
        "node": ["package.json", "*.ts", "*.tsx", "*.js"],
        "php": ["composer.json", "*.php"],
        "cobol": ["*.cbl", "*.cob"],
        "vb": ["*.vb"],
        "terraform": ["*.tf"],
        "docker": ["Dockerfile", "docker-compose.yml"],
    }
    found: Dict[str, List[str]] = {}
    for name, globs in patterns.items():
        hits: List[str] = []
        for g in globs:
            try:
                hits.extend(str(p.relative_to(root))
                            for p in root.rglob(g)
                            if "/.git/" not in str(p)
                            and "/node_modules/" not in str(p)
                            and "/bin/" not in str(p)
                            and "/obj/" not in str(p))
            except (OSError, ValueError):
                continue
        if hits:
            found[name] = hits[:5]  # sample
    return found


def _sev_emoji(sev: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🟢", "INFO": "⚪"}.get(sev.upper(), "⚫")


# ───────── 9 generadores de docs ────────────────────────────────────

def build_doc_01_code_scan(app, scan: Dict[str, Any]) -> str:
    md: List[str] = [yaml_frontmatter(
        title=f"01 · Code Scan · {app.short}",
        description=f"Output AIOS scan · {scan['count']} findings · baseline Fase 1",
        doc_type="discovery-01-code-scan", app=app)]
    md.append(f"# 01 · Code Scan · {app.short}\n\n")
    md.append(f"**Baseline AIOS** · {scan['count']} findings totales "
              f"· Tier {app.tier} ({app.criticality})\n\n")
    if scan.get("error"):
        md.append(f"⚠️ Scan error: `{scan['error']}`\n\n"
                  "**TODO**: revisar root del repo · re-correr `aios scan`.\n")
        return "".join(md)

    md.append("## Findings por severidad\n\n")
    md.append("| Severidad | Count |\n|---|---|\n")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = scan["by_severity"].get(sev, 0)
        md.append(f"| {_sev_emoji(sev)} {sev} | {c} |\n")
    md.append("\n## Top CWE detectados (top 10)\n\n| CWE | Count |\n|---|---|\n")
    top = sorted(scan["by_cwe"].items(), key=lambda x: -x[1])[:10]
    for cwe, c in top:
        md.append(f"| {cwe} | {c} |\n")

    md.append("\n## Muestra de findings (primeros 20)\n\n"
              "| Severidad | Detector | File:Line | Mensaje |\n"
              "|---|---|---|---|\n")
    for f in scan["findings"][:20]:
        sev = getattr(f, "severity", "?")
        det = getattr(f, "detector", "?")
        path = getattr(f, "path", "?")
        line = getattr(f, "line", "?")
        msg = str(getattr(f, "message", ""))[:80].replace("|", "\\|")
        md.append(f"| {_sev_emoji(sev)} {sev} | {det} | `{path}:{line}` | {msg} |\n")

    md.append("\n---\n\n"
              "**Siguiente**: `02_hallazgos_mapped.md` · mapeo CWE + compliance.\n")
    return "".join(md)


def build_doc_02_hallazgos_mapped(app, scan: Dict[str, Any]) -> str:
    md: List[str] = [yaml_frontmatter(
        title=f"02 · Hallazgos Consolidados · {app.short}",
        description="Cruce assessment externo + scan AIOS + workshops · CWE mapping",
        doc_type="discovery-02-hallazgos-mapped", app=app)]
    md.append(f"# 02 · Hallazgos Consolidados · {app.short}\n\n"
              "**Fuentes**: assessment externo (Softtek/Miatech) "
              "+ scan AIOS + workshops arquitectura.\n\n")

    md.append("## Hallazgos AIOS agrupados por CWE\n\n"
              "| CWE | Descripción breve | Count | Severidad dominante |\n"
              "|---|---|---|---|\n")
    cwe_stats: Dict[str, Dict[str, Any]] = {}
    for f in scan.get("findings", []):
        cwe = getattr(f, "cwe", "") or "N/A"
        sev = getattr(f, "severity", "INFO")
        if cwe not in cwe_stats:
            cwe_stats[cwe] = {"count": 0, "severities": Counter()}
        cwe_stats[cwe]["count"] += 1
        cwe_stats[cwe]["severities"][sev] += 1
    for cwe in sorted(cwe_stats, key=lambda c: -cwe_stats[c]["count"])[:15]:
        s = cwe_stats[cwe]
        dom_sev = s["severities"].most_common(1)[0][0] if s["severities"] else "?"
        md.append(f"| {cwe} | (ver CWE mitre) | {s['count']} "
                  f"| {_sev_emoji(dom_sev)} {dom_sev} |\n")

    md.append("\n## Consolidación assessment externo\n\n"
              "**TODO humano**: pegar tabla de hallazgos del assessment "
              "externo (Softtek/Miatech) + cruzar con la tabla AIOS. "
              "Identificar: duplicados · gaps · findings no detectados por scan.\n\n"
              "## Hallazgos workshops arquitectura\n\n"
              "**TODO humano**: extraer de minutas 20-abr (retro Antonio/Pedro) "
              "· decisiones arquitecturales pendientes · contradicciones stack.\n\n"
              "---\n\n"
              "**Siguiente**: `03_arq_as_is.md` · topología actual.\n")
    return "".join(md)


def build_doc_03_arq_as_is(app, stack: Dict[str, List[str]]) -> str:
    md: List[str] = [yaml_frontmatter(
        title=f"03 · Arquitectura AS-IS · {app.short}",
        description=f"Topología + stack + integraciones · Tier {app.tier}",
        doc_type="discovery-03-arq-as-is", app=app)]
    md.append(f"# 03 · Arquitectura AS-IS · {app.long_name}\n\n"
              f"**Stack AS-IS (plan v5)**: {humanize_stack(app.stack_as_is)}\n\n")

    md.append("## Stack detectado en repo\n\n")
    if not stack:
        md.append("⚠️ Sin stack detectable en el root. Posible skeleton "
                  "sin código (3 de 10 apps del plan v5 están en este estado).\n\n")
    else:
        md.append("| Lenguaje/Framework | Archivos sample |\n|---|---|\n")
        for lang, files in stack.items():
            sample = ", ".join(f"`{f}`" for f in files[:3])
            md.append(f"| **{lang}** | {sample} |\n")

    md.append("\n## Topología (alto nivel)\n\n"
              "**TODO humano** · diagrama AS-IS. Referencia:\n"
              "- Usar `aios analyze` para C4 Context L1 auto-generado\n"
              "- Drawio manual con constraints AMX (ver `feedback_diagram_constraints_checklist`)\n\n"
              "```mermaid\nflowchart TB\n"
              "    U[Usuario] --> Front[Frontend]\n"
              "    Front --> API[API Layer]\n"
              "    API --> DB[(Database)]\n"
              "    API --> Ext[Sistemas Externos]\n"
              "```\n\n"
              "## Integraciones detectadas\n\n"
              "**TODO humano** · tabla de integraciones IN/OUT con contraparte.\n\n"
              "## Volumetría\n\n"
              f"**TODO humano** · datos reales (requiere workshop con owner "
              f"{app.owner_tecnico.split('+')[0].strip() if '+' in app.owner_tecnico else app.owner_tecnico}).\n\n"
              "---\n\n**Siguiente**: `04_stakeholders.md`.\n")
    return "".join(md)


def build_doc_04_stakeholders(app) -> str:
    md: List[str] = [yaml_frontmatter(
        title=f"04 · Stakeholders · {app.short}",
        description=f"Owners funcional + técnico + governance · {app.criticality}",
        doc_type="discovery-04-stakeholders", app=app)]
    md.append(f"# 04 · Stakeholders · {app.long_name}\n\n")

    md.append("## Owners directos\n\n"
              f"| Rol | Nombre | Organización |\n|---|---|---|\n"
              f"| Owner funcional | {app.owner_funcional} | AMX |\n"
              f"| Owner técnico | {app.owner_tecnico} | Miatech/eTribe |\n\n"
              "## Governance transversal AMX\n\n"
              "| Rol | Nombre | Área |\n|---|---|---|\n"
              "| Arquitecto principal | Antonio Hernández Oropeza | AMX Arquitectura |\n"
              "| Arquitecto soporte | Pedro Emmanuel Abaonza | AMX Arquitectura |\n"
              "| Borde Arquitectura | Israel Miguel González Sandoval | AMX (aprueba ADRs) |\n"
              "| Ciber · salida prod | Miguel Rachid | AMX Ciberseguridad |\n"
              "| Red / AWS | Diego Zarate | AMX IT Drive |\n"
              "| óptimo (proyecto) | Carina | AMX PMO |\n"
              "| Continuidad Negocio | (TBD) | AMX |\n\n"
              "## Stakeholders Fase 1 Discovery\n\n"
              "**TODO humano** · completar:\n\n"
              "| Fase | Responsable | Entrega |\n|---|---|---|\n"
              "| Workshops técnicos | (equipo técnico Miatech) | Transcripciones |\n"
              "| Assessment externo | (consultor) | Reporte assessment |\n"
              "| Validación arquitectura | Borde Arq | ADR firmado |\n\n"
              "---\n\n**Siguiente**: `05_vulns.md`.\n")
    return "".join(md)


def build_doc_05_vulns(app, scan: Dict[str, Any]) -> str:
    md: List[str] = [yaml_frontmatter(
        title=f"05 · Vulnerabilidades y Compliance · {app.short}",
        description="Detalle vulns AIOS + compliance LFPDPPP/PCI-DSS/SOX/CFF/OWASP",
        doc_type="discovery-05-vulns", app=app)]
    md.append(f"# 05 · Vulnerabilidades y Compliance · {app.short}\n\n"
              f"**Tier**: `{app.tier}` · **Criticality**: {app.criticality}\n\n")

    md.append("## Breakdown vulns (scan actual)\n\n"
              "| Severidad | Count | % |\n|---|---|---|\n")
    total = max(1, scan.get("count", 0))
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = scan["by_severity"].get(sev, 0)
        md.append(f"| {_sev_emoji(sev)} {sev} | {c} | {100 * c / total:.1f}% |\n")

    md.append("\n## Compliance aplicable\n\n")
    comp_rows = [
        ("**LFPDPPP**", "✅ Sí (PII)", "PNRs · CFDIs · datos cliente"),
        ("**PCI-DSS**", "⚠️ Verificar", "Si procesa tarjetas → scope expandido"),
        ("**SOX**", "✅ Sí" if app.tier == "T0" else "⚠️ Revisar",
         "T0 Mission Critical = SOX-critical por default"),
        ("**CFF**" , "✅ Sí (CFDI)", "SAT · fiscal · retención 5 años"),
        ("**OWASP Top 10**", "✅ Baseline", "AIOS cubre 21/28 CWEs ≈ 75%"),
    ]
    md.append("| Marco | Aplica | Notas |\n|---|---|---|\n")
    for r in comp_rows:
        md.append(f"| {r[0]} | {r[1]} | {r[2]} |\n")

    md.append("\n## Baseline CYBER AMX\n\n"
              "Escaneos requeridos pre-prod (ver flujo aprobación AMX):\n\n"
              "1. **WIZ** · cloud posture\n"
              "2. **Veracode** · SAST\n"
              "3. **Prisma** · container scan\n"
              "4. **Tenable** · VM + network\n\n"
              "**TODO humano** · pegar resultados de cada scan + "
              "plan remediación para findings no-waiver.\n\n"
              "## Top CWEs críticos\n\n"
              "**TODO** · correr `aios compliance-report` + pegar highlights.\n\n"
              "---\n\n**Siguiente**: `06_deps.md`.\n")
    return "".join(md)


def build_doc_06_deps(app, stack: Dict[str, List[str]]) -> str:
    md: List[str] = [yaml_frontmatter(
        title=f"06 · Dependencias · {app.short}",
        description="Stack + deps externas + upgrade targets",
        doc_type="discovery-06-deps", app=app)]
    md.append(f"# 06 · Dependencias · {app.short}\n\n"
              f"**Stack AS-IS**: {humanize_stack(app.stack_as_is)}\n\n")

    md.append("## Lockfiles detectados\n\n")
    lockfiles = {
        "dotnet": "packages.lock.json / *.csproj",
        "node": "package-lock.json / yarn.lock",
        "python": "poetry.lock / requirements.txt",
        "java": "pom.xml / build.gradle",
        "php": "composer.lock",
    }
    found_any = False
    for lang in stack:
        if lang in lockfiles:
            md.append(f"- **{lang}** · `{lockfiles[lang]}`\n")
            found_any = True
    if not found_any:
        md.append("⚠️ Sin lockfiles detectables. Si el app tiene código "
                  "pero sin lockfile → gap supply-chain crítico.\n")

    md.append("\n## Upgrade targets (plan v5)\n\n"
              "| Capa | AS-IS | TO-BE | Justificación |\n|---|---|---|---|\n"
              "| Runtime | (ver stack) | LTS vigente | soporte + seguridad |\n"
              "| Base de datos | (ver stack) | Aurora MySQL 8 | patrón AMX |\n"
              "| Auth | (ver stack) | OIDC AMX | SSO corporativo |\n"
              "| Observability | (ver stack) | OTel + CloudWatch | patrón AMX |\n\n"
              "**TODO humano** · completar upgrade target por cada "
              "dependencia crítica con EOL < 12 meses.\n\n"
              "## Dependencias externas (integraciones)\n\n"
              "**TODO humano** · tabla IN/OUT con owner.\n\n"
              "## Supply-chain\n\n"
              "**TODO**: correr `aios sbom` + `aios npm-audit` / `aios trivy-scan` "
              "y pegar resumen.\n\n"
              "---\n\n**Siguiente**: `07_preguntas_nuevas.md`.\n")
    return "".join(md)


def build_doc_07_preguntas_nuevas(app) -> str:
    md: List[str] = [yaml_frontmatter(
        title=f"07 · Preguntas Pendientes · {app.short}",
        description="Top bloqueadoras Fase 1 + categorizadas por dominio",
        doc_type="discovery-07-preguntas-nuevas", app=app)]
    md.append(f"# 07 · Preguntas Pendientes · {app.short}\n\n"
              "Consolidado de preguntas sin respuesta al cierre Fase 1 "
              "· categorizadas por dominio.\n\n")

    categorias = [
        ("Arquitectura", ["Stack target · confirmar tecnologías con Borde Arq",
                          "Topología TO-BE · opción A vs B (ver ADR)",
                          "Patrones AMX aplicables · LeanIX mapping"]),
        ("Datos", ["Schema real · volumen · ventanas batch",
                   "Migración · cutover vs parallel run",
                   "PII inventory · cumplimiento LFPDPPP"]),
        ("Integraciones", ["Endpoints reales · contratos · SLAs",
                           "Fallbacks · timeouts · circuit breakers",
                           "Authentication entre sistemas"]),
        ("Seguridad · Ciber", ["KMS tickets por servicio",
                               "SSO OIDC · IDP corporativo",
                               "Secrets management · rotation"]),
        ("Operación", ["Runbooks · procedimientos deploy",
                       "DR target · RTO/RPO oficiales Continuidad",
                       "Observability · dashboards · alerts"]),
        ("Negocio", ["Impacto downstream · consumidores",
                     "SLA cliente final · penalidades",
                     "Timeline negocio · hitos intermedios"]),
    ]

    for cat, qs in categorias:
        md.append(f"\n### {cat}\n\n")
        for i, q in enumerate(qs, 1):
            md.append(f"- [ ] Q · {q}\n")

    md.append("\n## TOP 5 bloqueadoras (primeros 15 min de workshop)\n\n"
              "**TODO humano** · extraer las 5 más urgentes del listado anterior "
              "+ asignar owner + deadline.\n\n"
              "| # | Pregunta | Owner | Deadline |\n|---|---|---|---|\n"
              "| 1 | ... | ... | YYYY-MM-DD |\n\n"
              "---\n\n**Siguiente**: `08_bloqueadores.md`.\n")
    return "".join(md)


def build_doc_08_bloqueadores(app) -> str:
    md: List[str] = [yaml_frontmatter(
        title=f"08 · Bloqueadores Fase 1 · {app.short}",
        description="Blockers absolutos + status mitigación",
        doc_type="discovery-08-bloqueadores", app=app)]
    md.append(f"# 08 · Bloqueadores Fase 1 · {app.short}\n\n"
              "Blockers que impiden avanzar a Fase 2 si no se resuelven.\n\n")

    md.append("## Cross-app blockers (plan v5 · aplican a todas)\n\n")
    if CROSS_APP_BLOCKERS:
        md.append("| # | Blocker | Status |\n|---|---|---|\n")
        for i, b in enumerate(CROSS_APP_BLOCKERS, 1):
            md.append(f"| {i} | {b} | ⏸ pendiente |\n")
    else:
        md.append("_(sin blockers cross-app registrados en plan_v5)_\n")

    md.append("\n## Bloqueadores específicos del app\n\n"
              "**TODO humano** · completar tabla:\n\n"
              "| # | Blocker | Impacto | Owner | Deadline | Status |\n"
              "|---|---|---|---|---|---|\n"
              "| B-01 | Acceso repositorio legacy | Bloquea scan AIOS | ... | YYYY-MM-DD | ⏸ |\n"
              "| B-02 | VPN red Miatech | Bloquea integración real | IT AMX | ... | ⏸ |\n"
              "| B-03 | Schema BD real | Bloquea EF migrations reales | DBA Miatech | D5 | ⏸ |\n"
              "| B-04 | KMS real AMX | Bloquea cifrado prod | Toño/Arturo IT Drive | 28-abr | 🔴 |\n"
              "| B-05 | IDP corporativo SSO | Bloquea auth real | Diego Zarate | ... | ⏸ |\n\n"
              "## Matriz mitigación local\n\n"
              "| Blocker | ¿Mitigable con pruebas locales? | Mecanismo |\n|---|---|---|\n"
              "| Schema BD | ⚠️ Parcial | Docker MySQL/MariaDB + EF migrations |\n"
              "| KMS | ❌ No compliance | LocalStack simula API pero no cert |\n"
              "| SSO | ⚠️ Parcial | Keycloak local cubre OIDC flow |\n"
              "| Endpoints externos | ⚠️ Parcial | WireMock + contract tests |\n"
              "| VPN/Red | ❌ No | Control organizacional |\n\n"
              "---\n\n**Siguiente**: `09_risk_register.md`.\n")
    return "".join(md)


def build_doc_09_risk_register(app, scan: Dict[str, Any]) -> str:
    md: List[str] = [yaml_frontmatter(
        title=f"09 · Risk Register Inicial · {app.short}",
        description=f"Riesgos probabilidad × impacto · Tier {app.tier}",
        doc_type="discovery-09-risk-register", app=app)]
    md.append(f"# 09 · Risk Register Inicial · {app.long_name}\n\n"
              f"**Tier**: `{app.tier}` · **Criticality**: {app.criticality}\n\n"
              "Probabilidad: BAJA(1) · MEDIA(2) · ALTA(3)\n"
              "Impacto: BAJO(1) · MEDIO(2) · ALTO(3) · CRÍTICO(4)\n"
              "Score = Probabilidad × Impacto · >=6 requiere mitigación activa.\n\n")

    md.append("## Riesgos heurísticos por Tier\n\n")
    tier_risks = {
        "T0": [
            ("Falla DR · RTO excedido", 2, 4, "Parallel-run + runbook DR real"),
            ("Data loss · RPO excedido", 1, 4, "Aurora Multi-AZ + backups PITR"),
            ("Compliance SOX breach", 2, 4, "Audit trail + immutable logs"),
            ("Vulnerabilidad zero-day crítica", 2, 3, "Dependabot + WIZ continuo"),
        ],
        "T1": [
            ("Breach compliance regulatorio", 2, 3, "Compliance scan pre-prod"),
            ("Retraso go-live", 2, 3, "Buffer 15% en cronograma"),
        ],
        "T2": [
            ("Deuda técnica acumulada post-migración", 2, 2, "Refactor backlog"),
        ],
        "T3": [("Obsolescencia framework", 1, 2, "Plan upgrade anual")],
    }
    base = tier_risks.get(app.tier, tier_risks["T2"])
    md.append("| # | Riesgo | P | I | Score | Mitigación |\n"
              "|---|---|---|---|---|---|\n")
    for i, (desc, p, impact, mit) in enumerate(base, 1):
        md.append(f"| R-{i:02d} | {desc} | {p} | {impact} | **{p * impact}** | {mit} |\n")

    md.append("\n## Riesgos desde findings AIOS\n\n")
    crit = scan["by_severity"].get("CRITICAL", 0)
    high = scan["by_severity"].get("HIGH", 0)
    if crit > 0:
        md.append(f"- 🔴 **R-AIOS-C** · {crit} CRITICAL findings · "
                  "Probabilidad 3 × Impacto 4 = **12** · **URGENTE**\n")
    if high > 0:
        md.append(f"- 🟠 **R-AIOS-H** · {high} HIGH findings · "
                  "Probabilidad 2 × Impacto 3 = **6** · mitigación activa\n")
    if crit == 0 and high == 0:
        md.append("_(sin CRITICAL/HIGH findings AIOS al cierre de este scan)_\n")

    md.append("\n## Riesgos específicos del app\n\n"
              "**TODO humano** · completar con riesgos identificados "
              "en workshops técnicos + negocio. Formato:\n\n"
              "| # | Descripción | P | I | Score | Mitigación | Owner |\n"
              "|---|---|---|---|---|---|---|\n"
              "| R-APP-01 | ... | 2 | 3 | 6 | ... | ... |\n\n"
              "## Heat map\n\n"
              "```\n"
              "Impact ↑\n"
              "  4 │         [R-01]  [R-AIOS-C]\n"
              "  3 │         [R-02]  [R-AIOS-H]\n"
              "  2 │  [R-03]\n"
              "  1 │\n"
              "    └────────────────────────→ Probabilidad\n"
              "        1      2      3\n"
              "```\n\n"
              "---\n\n**Final del paquete Discovery Fase 1**. "
              "Siguiente · `aios phase1-report` para Evidence Bundle consolidado.\n")
    return "".join(md)


# ───────── orchestrator principal ────────────────────────────────────

def generate_discovery_docs(app_key: str, root: Path,
                            overwrite: bool = False,
                            pdf: bool = False) -> Dict[str, Any]:
    """Genera los 9 docs Discovery · retorna dict con paths generados + stats.

    Si `pdf=True`, después de escribir cada MD genera también el PDF equivalente
    en `<out_dir>/pdfs/<filename>.pdf` usando weasyprint. Si weasyprint no está
    disponible, los PDFs se omiten silenciosamente y se reporta en el dict.
    """
    app = resolve_app(app_key)
    out_dir = ensure_output_dir(default_output_dir(root))

    scan = _run_scan(root)
    stack = _detect_stack(root)

    builders = [
        ("01_code_scan.md",         lambda: build_doc_01_code_scan(app, scan)),
        ("02_hallazgos_mapped.md",  lambda: build_doc_02_hallazgos_mapped(app, scan)),
        ("03_arq_as_is.md",         lambda: build_doc_03_arq_as_is(app, stack)),
        ("04_stakeholders.md",      lambda: build_doc_04_stakeholders(app)),
        ("05_vulns.md",             lambda: build_doc_05_vulns(app, scan)),
        ("06_deps.md",              lambda: build_doc_06_deps(app, stack)),
        ("07_preguntas_nuevas.md",  lambda: build_doc_07_preguntas_nuevas(app)),
        ("08_bloqueadores.md",      lambda: build_doc_08_bloqueadores(app)),
        ("09_risk_register.md",     lambda: build_doc_09_risk_register(app, scan)),
    ]

    pdf_dir = out_dir / "pdfs" if pdf else None
    if pdf_dir is not None:
        pdf_dir.mkdir(parents=True, exist_ok=True)

    results: List[Dict[str, Any]] = []
    pdf_total = 0
    pdf_ok = 0
    for filename, build_fn in builders:
        md_path = out_dir / filename
        existed = md_path.exists()
        if existed and not overwrite:
            entry = {"file": filename, "status": "skipped-exists",
                     "path": str(md_path)}
        else:
            content = build_fn()
            write_doc(md_path, content)
            entry = {"file": filename, "status": "written",
                     "path": str(md_path), "lines": content.count("\n")}

        if pdf and pdf_dir is not None and md_path.exists():
            pdf_total += 1
            pdf_path = pdf_dir / filename.replace(".md", ".pdf")
            existed_pdf = pdf_path.exists()
            if existed_pdf and not overwrite:
                entry["pdf_status"] = "skipped-exists"
                entry["pdf_path"] = str(pdf_path)
            else:
                success = md_to_pdf(md_path, pdf_path)
                if success:
                    pdf_ok += 1
                    entry["pdf_status"] = "written"
                    entry["pdf_path"] = str(pdf_path)
                else:
                    entry["pdf_status"] = "failed"
                    entry["pdf_path"] = str(pdf_path)

        results.append(entry)

    report: Dict[str, Any] = {
        "app": app.short, "tier": app.tier, "out_dir": str(out_dir),
        "scan_findings": scan.get("count", 0),
        "scan_error": scan.get("error"),
        "stack_detected": list(stack.keys()),
        "docs": results,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if pdf:
        report["pdf_enabled"] = True
        report["pdf_dir"] = str(pdf_dir) if pdf_dir else None
        report["pdf_generated"] = pdf_ok
        report["pdf_total"] = pdf_total
        report["pdf_weasyprint_available"] = pdf_ok > 0 or pdf_total == 0
    return report
