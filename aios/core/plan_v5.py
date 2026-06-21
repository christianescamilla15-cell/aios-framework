"""v3.5.1 · Plan de Trabajo v5 · Finance Operations Modernization ACME.

Integra el framework con el plan de trabajo v5 (Justificacion_Plan_v5_23abr.md).
Expone metadata de los 10 aplicativos del scope eTrive: Tier · go-live · patrones
obligatorios por Tier · bloqueantes cross-app. Usado por:

- `aios phase1-report` para generar el Discovery Package consolidado
- Futuros subcomandos (phase2-report · fase gates · etc.)

Fuente autoritativa: plan v5 §9 (cronograma) + §4 (Fase 2 patrones) + §10 (riesgos).
No reemplaza al MD del plan; lo expone programáticamente.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class AppMetadata:
    """Metadata de aplicativo del plan v5."""
    app_id: int          # # en numeración eTrive
    excel_id: str        # # en Excel V5 hoja (si distinto)
    short: str           # nombre corto
    long_name: str       # nombre oficial
    tier: str            # "T0" / "T1" / "T2" / "T3"
    criticality: str     # "Mission Critical" · "Compliance" · "Batch baja freq" · etc.
    stack_as_is: str     # stack actual
    go_live: str         # fecha objetivo
    arranque_fase1: str  # fecha arranque Fase 1
    duracion_weeks: str  # rango semanas
    owner_funcional: str
    owner_tecnico: str
    codigo_disponible: bool = False
    notas: str = ""


# ════════════════════════════════════════════════════════════════════
# Plan v5 § 9 · cronograma por aplicativo (fuente: Justificacion_Plan_v5)
# ════════════════════════════════════════════════════════════════════
APPS: Dict[str, AppMetadata] = {
    "fleet_ops_app": AppMetadata(
        app_id=1, excel_id="1",
        short="FLEET_OPS_APP", long_name="Sistema de Conciliación de Facturas",
        tier="T0", criticality="Mission Critical · SOX",
        stack_as_is="C# ASP.NET 4.6.1 + VB.NET 60% + PHP 24% + Aurora MySQL 8.0.39",
        go_live="2026-09-10", arranque_fase1="2026-04-06",
        duracion_weeks="20-25",
        owner_funcional="Rocío Anaya (ACME)",
        owner_tecnico="Jacobo Ramirez + Nelson del Ángel (Miatech)",
        codigo_disponible=True,
        notas="Única app 100% AWS del ecosistema · V2 Miatech en paralelo (duplicidad a resolver)",
    ),
    "arc": AppMetadata(
        app_id=2, excel_id="2",
        short="ARC", long_name="Reembolsos ARC",
        tier="T1", criticality="Compliance regulatorio",
        stack_as_is="TBD (scaffold · sin código entregado)",
        go_live="2026-08-15", arranque_fase1="2026-04-20",
        duracion_weeks="11-14",
        owner_funcional="TBD", owner_tecnico="Miatech",
        codigo_disponible=False,
    ),
    "bsp": AppMetadata(
        app_id=3, excel_id="3",
        short="BSP", long_name="Reembolsos BSP",
        tier="T1", criticality="Compliance regulatorio",
        stack_as_is="Robot RPA IATA · TBD (sin código entregado)",
        go_live="2026-08-10", arranque_fase1="2026-04-20",
        duracion_weeks="11-14",
        owner_funcional="TBD", owner_tecnico="Miatech",
        codigo_disponible=False,
    ),
    "cfdis": AppMetadata(
        app_id=4, excel_id="4",
        short="CFDIs", long_name="Descarga CFDIs",
        tier="T1", criticality="Compliance regulatorio SAT",
        stack_as_is="3 componentes + cliente Python (sin código entregado)",
        go_live="2026-08-24", arranque_fase1="2026-04-27",
        duracion_weeks="11-14",
        owner_funcional="TBD", owner_tecnico="Miatech",
        codigo_disponible=False,
    ),
    "srg": AppMetadata(
        app_id=5, excel_id="5",
        short="SRG", long_name="Sistema de Registro y Control de Venta de Grupos",
        tier="T3", criticality="Batch baja frecuencia · intranet-only · 8x5",
        stack_as_is=".NET 7 + Angular 15 + TinyMCE + SQL Server + Windows Server 2012 R2 EOL",
        go_live="2026-07-08", arranque_fase1="2026-05-04",
        duracion_weeks="8-10",
        owner_funcional="Gabriela Vázquez + Karina Cedillo (ACME)",
        owner_tecnico="Nelson + Cristian (Miatech)",
        codigo_disponible=True,
        notas="Clientes AcmeAir + Delta · única app con 112 tests unit · discrepancia T1 vs T3 vs matriz v3",
    ),
    "asr": AppMetadata(
        app_id=6, excel_id="6",
        short="ASR", long_name="Reembolsos Especiales",
        tier="T2", criticality="Operación continua",
        stack_as_is="Python + Flask · MySQL + DB2 · 81 usuarios (sin código entregado)",
        go_live="2026-09-20", arranque_fase1="2026-06-01",
        duracion_weeks="11-14",
        owner_funcional="TBD", owner_tecnico="Miatech",
        codigo_disponible=False,
    ),
    "robot": AppMetadata(
        app_id=7, excel_id="8",  # Excel V5 numera distinto
        short="Robot", long_name="Robot de Cálculo de Reembolso · Venta Indirecta",
        tier="T0", criticality="Mission Critical · SOX · motor compartido 3 canales",
        stack_as_is="VB.NET + SABRE SOAP · 954K LoC · CCNumber plaintext PCI violation · CVSS 9.8 command injection",
        go_live="2026-09-24", arranque_fase1="2026-04-06",
        duracion_weeks="20-25",
        owner_funcional="Javier Toledo Tovar (ACME · Gerente Senior Ingresos)",
        owner_tecnico="Miatech",
        codigo_disponible=True,
        notas="Motor compartido BSP+ARC+ASR · cutover secuencial por canal · Globalizador sin código · PoC eTrive 43 tests Python mitigó CVSS 9.8",
    ),
    "com_directas": AppMetadata(
        app_id=8, excel_id="9",
        short="Com-Directas", long_name="Comisiones Directas · FOB Reporte IATAs Perú",
        tier="T3", criticality="Batch baja frecuencia",
        stack_as_is="COBOL ILE + Java + HTML · AS400 DB2 V7R4M0 · on-prem Perú ATOS-LIMA",
        go_live="2026-07-15", arranque_fase1="2026-05-18",
        duracion_weeks="8-10",
        owner_funcional="Julio Yauri (ASI ACME)",
        owner_tecnico="TBD · Gustavo eTrive tiene expertise COBOL",
        codigo_disponible=True,
        notas="PoC local VB.NET genérico · legacy real COBOL pendiente entrega · Prod_FOB = app más severa (48 BLOCKER · 17 crítical)",
    ),
    "com_indirectas": AppMetadata(
        app_id=9, excel_id="10",
        short="Com-Indirectas", long_name="Comisiones Indirectas",
        tier="T3", criticality="Batch baja frecuencia",
        stack_as_is="PHP + Python + COBOL ILE + Aurora + DB2 (sin código entregado)",
        go_live="2026-07-22", arranque_fase1="2026-05-18",
        duracion_weeks="8-10",
        owner_funcional="TBD", owner_tecnico="Miatech",
        codigo_disponible=False,
    ),
    "noshow": AppMetadata(
        app_id=10, excel_id="7",
        short="NoShow", long_name="NoShow Report",
        tier="T2", criticality="Operación continua",
        stack_as_is=".NET Framework 4.7 → .NET 8 LTS (refactorizado)",
        go_live="2026-10-15", arranque_fase1="2026-06-01",
        duracion_weeks="11-14",
        owner_funcional="Alberto Ibrahim (destinatario evidence-bundle)",
        owner_tecnico="eTrive (refactorizado)",
        codigo_disponible=True,
        notas="Piloto completo cerrado 23-abr · 24/28 findings cerrados · evidence-bundle listo · base de validación plan v5",
    ),
}


# ════════════════════════════════════════════════════════════════════
# Patrones obligatorios por Tier (plan v5 §4 + §6)
# ════════════════════════════════════════════════════════════════════
TIER_PATTERNS: Dict[str, Dict[str, List[str]]] = {
    "T0": {
        "compute": [
            "EKS multi-región (Virginia + Oregon activo-activo)",
            "NO Fargate single-AZ",
        ],
        "edge": ["Akamai WAF + CDN + DNS obligatorio endpoint público"],
        "secrets": [
            "KMS CMK DEDICADA POR SERVICIO",
            "ej. fleet_ops_app-api · fleet_ops_app-db · fleet_ops_app-logs · fleet_ops_app-secrets",
        ],
        "refactor_pattern": [
            "Strangler Fig OBLIGATORIO",
            "dark launch + parallel run ≥ 2 ciclos contables",
            "cut-over incremental por módulo · no big-bang",
        ],
        "coverage": ["≥ 80% crítico · 100% módulos SOX"],
        "gates": [
            "DR drill obligatorio antes cutover",
            "WIZ → Veracode → Prisma → Tenable (orden retro 20-abr)",
            "Sign-off Dirección + Miguel Rachid",
        ],
        "rto_rpo": ["RTO < 1h · RPO < 5min"],
        "duration": ["20-25 semanas"],
    },
    "T1": {
        "compute": ["EKS o serverless (no EC2)"],
        "edge": ["Akamai WAF + CDN + DNS"],
        "secrets": ["KMS CMK + Secrets Manager"],
        "refactor_pattern": ["Refactor directo con parallel run acotado"],
        "coverage": ["≥ 70% crítico · 100% módulos SOX"],
        "gates": ["WIZ + Veracode + Prisma + Tenable", "Sign-off Miguel Rachid"],
        "rto_rpo": ["RTO < 4h · RPO < 15min"],
        "duration": ["11-14 semanas"],
    },
    "T2": {
        "compute": ["Fargate single-AZ admitido · EKS opcional"],
        "edge": ["Akamai WAF si endpoint público · intranet no requiere"],
        "secrets": ["KMS CMK + Secrets Manager · CMK compartida admitida"],
        "refactor_pattern": [
            "Refactor directo (estilo piloto NoShow)",
            "Smoke + happy path",
        ],
        "coverage": ["≥ 60%"],
        "gates": ["WIZ + Veracode + Prisma + Tenable"],
        "rto_rpo": ["RTO < 8h · RPO < 1h"],
        "duration": ["11-14 semanas"],
    },
    "T3": {
        "compute": ["Fargate single-AZ · batch / scheduled"],
        "edge": ["Sin Akamai si intranet-only"],
        "secrets": ["KMS CMK compartida admitida · Secrets Manager"],
        "refactor_pattern": ["Refactor directo · sin parallel run estricto"],
        "coverage": ["≥ 60%"],
        "gates": ["WIZ + Veracode + Prisma + Tenable (más ligeros)"],
        "rto_rpo": ["RTO < 24h · RPO < 4h"],
        "duration": ["8-10 semanas"],
    },
}


# ════════════════════════════════════════════════════════════════════
# Bloqueantes cross-app (plan v5 §10 + update 23-abr)
# ════════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class CrossAppBlocker:
    blocker_id: str
    title: str
    description: str
    impact: str
    owner: str
    deadline: str
    status: str


CROSS_APP_BLOCKERS: List[CrossAppBlocker] = [
    CrossAppBlocker(
        blocker_id="B-001",
        title="Sin ambiente DEV/QA (TRANSVERSAL · las 10 apps)",
        description=(
            "Ninguno de los 10 aplicativos cuenta con DEV/QA · sólo producción. "
            "Refactor seguro imposible con usuarios activos. Mitigación táctica: "
            "Visual Studio local (en descarga 23-abr) + self-hosted CI runner WDAC. "
            "Greenfield AWS ACME es solución estructural."
        ),
        impact="TODAS · precede Fase 2",
        owner="Víctor + Antonio Oropeza + Christian",
        deadline="2026-04-28",
        status="open",
    ),
    CrossAppBlocker(
        blocker_id="B-AWS-ACCT",
        title="Cuenta AWS Greenfield ACME (no Miatech)",
        description=(
            "SLA 24h post visto-bueno líder. Precede VPC + KMS + IAM + pipelines."
        ),
        impact="TODAS · arranque Fase 2",
        owner="Víctor Araiza",
        deadline="2026-04-28",
        status="open",
    ),
    CrossAppBlocker(
        blocker_id="B-KMS",
        title="KMS ACME CMK · 1 POR SERVICIO",
        description=(
            "Retro 20-abr Antonio H. Oropeza. GateOne portal autoservicio o ACME chat."
        ),
        impact="T0 + T1",
        owner="Antonio H. Oropeza · líder ACME",
        deadline="2026-05-05",
        status="open",
    ),
    CrossAppBlocker(
        blocker_id="B-TIERS",
        title="Documento TIERS (sitio Dynamo)",
        description=(
            "Clasificación + RTO/RPO + criticidad por app. "
            "Necesario para resolver discrepancia SRG T1 vs T3 entre matriz v3 y plan v5."
        ),
        impact="TODAS · Borde Arq",
        owner="Edgar Castillo + Israel Miguel",
        deadline="2026-04-28",
        status="open",
    ),
    CrossAppBlocker(
        blocker_id="B-WDAC",
        title="WDAC bloquea dotnet test local",
        description=(
            "Riesgo crítico #6 plan v5. Evidenciado en piloto NoShow (23-abr). "
            "Mitigación: self-hosted GitHub Enterprise runner. "
            "Afecta a TODOS los aplicativos .NET."
        ),
        impact="TODOS los .NET (6+ apps del scope)",
        owner="Christian + Luis Ertuche + Miguel Rachid",
        deadline="2026-04-28",
        status="open",
    ),
    CrossAppBlocker(
        blocker_id="B-KIRO",
        title="Licencia Kiro 1000 creds/mes",
        description="Aprobada por Elías · Selena coordina distribución para el equipo.",
        impact="TODAS",
        owner="Selena (PM ITERA)",
        deadline="2026-04-28",
        status="open",
    ),
    CrossAppBlocker(
        blocker_id="B-AIOS-GATES",
        title="AIOS 4 gates pre-CYBER integrados al pipeline",
        description=(
            "Plan v5 §3 formaliza aios release/drift/exfil/runtime-data como pre-gate "
            "obligatorio antes de los 4 escaneos corporativos."
        ),
        impact="TODAS · cierre Fase 2-4",
        owner="Christian + Luis",
        deadline="2026-05-15",
        status="open",
    ),
]


# ════════════════════════════════════════════════════════════════════
# Fase 1 Discovery · entregables (plan v5 §3.4)
# ════════════════════════════════════════════════════════════════════
PHASE1_DELIVERABLES: List[Dict[str, str]] = [
    {"num": "01", "file": "01_code_scan.md",
     "title": "Code Scan",
     "desc": "Assessment Softtek + baseline AIOS · hallazgos por severidad"},
    {"num": "02", "file": "02_hallazgos_mapped.md",
     "title": "Hallazgos Consolidados",
     "desc": "Cruce assessment + workshops + scan propio · mapeo a CWE"},
    {"num": "03", "file": "03_arq_as_is.md",
     "title": "Arquitectura AS-IS",
     "desc": "Topología + stack + integraciones + volumetría"},
    {"num": "04", "file": "04_stakeholders.md",
     "title": "Stakeholders",
     "desc": "Owners funcional + técnico + governance transversal"},
    {"num": "05", "file": "05_vulns.md",
     "title": "Vulnerabilidades y Compliance",
     "desc": "Detalle vulns + compliance aplicable + baseline CYBER"},
    {"num": "06", "file": "06_deps.md",
     "title": "Dependencias",
     "desc": "Stack + integraciones externas + upgrade target"},
    {"num": "07", "file": "07_preguntas_nuevas.md",
     "title": "Preguntas Pendientes",
     "desc": "Top bloqueadoras + categorizadas por dominio"},
    {"num": "08", "file": "08_bloqueadores.md",
     "title": "Bloqueadores Fase 1",
     "desc": "Blockers absolutos + status mitigación"},
    {"num": "09", "file": "09_risk_register.md",
     "title": "Risk Register Inicial",
     "desc": "Riesgos catalogados por probabilidad × impacto"},
]


def get_app(key: str) -> AppMetadata | None:
    """Retorna metadata de aplicativo por short name (case-insensitive)."""
    key_norm = key.lower().replace("-", "_").replace(" ", "_")
    return APPS.get(key_norm)


def list_apps_by_tier(tier: str) -> List[AppMetadata]:
    """Retorna aplicativos del plan v5 filtrados por Tier."""
    return [app for app in APPS.values() if app.tier == tier.upper()]


def patterns_for_tier(tier: str) -> Dict[str, List[str]]:
    """Retorna patrones obligatorios del Tier según plan v5."""
    return TIER_PATTERNS.get(tier.upper(), {})


def get_cross_app_blockers(status: str | None = None) -> List[CrossAppBlocker]:
    """Retorna bloqueantes cross-app · filtra por status si se indica."""
    if status is None:
        return CROSS_APP_BLOCKERS
    return [b for b in CROSS_APP_BLOCKERS if b.status == status]
