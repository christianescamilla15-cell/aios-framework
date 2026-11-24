"""Portafolio de modernización · metadata de las aplicaciones, patrones por TIER y bloqueantes.

Lo consumen `aios discovery-generate` (los 9 documentos de la fase 1) y `aios phase1-report`
(el paquete consolidado). Los datos describen a **Acme Corp, una organización ficticia**: las
aplicaciones son las mismas 8 de `aios/governance/rules/tiers.yaml`, con cifras y dueños inventados.
Para un portafolio real, reemplaza `APPS`, `TIER_PATTERNS` y `CROSS_APP_BLOCKERS`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class AppMetadata:
    """Metadata de una aplicación del portafolio."""
    app_id: int
    short: str           # nombre corto
    long_name: str       # nombre largo
    tier: str            # "T0" / "T1" / "T2" / "T3"
    criticality: str     # "Crítica · ingresos" · "Batch de baja frecuencia" · etc.
    stack_as_is: str     # stack actual
    go_live: str         # fecha objetivo (AAAA-MM-DD)
    arranque_fase1: str  # arranque de la fase 1
    duracion_weeks: str  # rango de semanas
    owner_funcional: str
    owner_tecnico: str
    codigo_disponible: bool = False
    notas: str = ""


# ════════════════════════════════════════════════════════════════════
# Aplicaciones (ficticias)
# ════════════════════════════════════════════════════════════════════
APPS: Dict[str, AppMetadata] = {
    "billing": AppMetadata(
        app_id=1, short="Billing", long_name="Facturación a clientes",
        tier="T0", criticality="Crítica · ingresos",
        stack_as_is="C# ASP.NET Framework 4.8 + SQL Server 2016",
        go_live="2027-03-15", arranque_fase1="2026-12-01", duracion_weeks="20-25",
        owner_funcional="Dirección de Finanzas", owner_tecnico="Alicia Moreno + equipo de entrega",
        codigo_disponible=True,
        notas="Cierre mensual: el corte no puede caer en los últimos 3 días hábiles del mes",
    ),
    "orders": AppMetadata(
        app_id=2, short="Orders", long_name="Captura y seguimiento de pedidos",
        tier="T1", criticality="Estratégica · canal de venta",
        stack_as_is="VB.NET WinForms + SQL Server",
        go_live="2027-02-01", arranque_fase1="2026-12-01", duracion_weeks="11-14",
        owner_funcional="Dirección Comercial", owner_tecnico="Bruno Quintana",
        codigo_disponible=True,
    ),
    "shipping": AppMetadata(
        app_id=3, short="Shipping", long_name="Guías y rastreo de envíos",
        tier="T1", criticality="Estratégica · entrega",
        stack_as_is="Java 8 monolito + Oracle",
        go_live="2027-02-15", arranque_fase1="2026-12-15", duracion_weeks="11-14",
        owner_funcional="Dirección de Operaciones", owner_tecnico="Carmen Solís",
        codigo_disponible=False,
    ),
    "faxgw": AppMetadata(
        app_id=4, short="FaxGateway", long_name="Pasarela de fax heredada",
        tier="T1", criticality="Fuera de alcance · se retira",
        stack_as_is="Servicio Windows (sin código fuente)",
        go_live="n/a", arranque_fase1="n/a", duracion_weeks="0",
        owner_funcional="Dirección de Operaciones", owner_tecnico="proveedor actual",
        codigo_disponible=False,
        notas="Se retira sin migrar",
    ),
    "partners": AppMetadata(
        app_id=5, short="Partners", long_name="Portal de socios comerciales",
        tier="T2", criticality="Táctica · intranet y extranet 8x5",
        stack_as_is=".NET 7 + Angular 15 + SQL Server",
        go_live="2027-01-20", arranque_fase1="2026-12-01", duracion_weeks="8-10",
        owner_funcional="Dirección Comercial", owner_tecnico="Bruno Quintana",
        codigo_disponible=True,
    ),
    "support": AppMetadata(
        app_id=6, short="Support", long_name="Mesa de ayuda interna",
        tier="T2", criticality="Operación continua",
        stack_as_is="PHP 7 + MySQL 5.7",
        go_live="2027-03-01", arranque_fase1="2027-01-10", duracion_weeks="11-14",
        owner_funcional="Dirección de Personas", owner_tecnico="Carmen Solís",
        codigo_disponible=False,
    ),
    "payments": AppMetadata(
        app_id=7, short="Payments", long_name="Cobro con tarjeta",
        tier="T0", criticality="Crítica · alcance PCI",
        stack_as_is="Java 11 + Spring Boot + PostgreSQL",
        go_live="2027-04-01", arranque_fase1="2026-12-01", duracion_weeks="20-25",
        owner_funcional="Dirección de Finanzas", owner_tecnico="Daniel Vega",
        codigo_disponible=True,
    ),
    "reports": AppMetadata(
        app_id=8, short="Reports", long_name="Reportes nocturnos de ventas",
        tier="T2", criticality="Batch de baja frecuencia",
        stack_as_is="Python 3.8 en cron + PostgreSQL",
        go_live="2027-01-15", arranque_fase1="2026-12-01", duracion_weeks="8-10",
        owner_funcional="Dirección de Finanzas", owner_tecnico="Alicia Moreno",
        codigo_disponible=True,
    ),
}


# ════════════════════════════════════════════════════════════════════
# Patrones obligatorios por TIER
# ════════════════════════════════════════════════════════════════════
TIER_PATTERNS: Dict[str, Dict[str, List[str]]] = {
    "T0": {
        "compute": ["Contenedores en dos regiones, activo-activo", "Sin cómputo en una sola zona"],
        "edge": ["CDN + WAF delante de todo endpoint público"],
        "secrets": ["Una llave KMS administrada por el cliente POR SERVICIO"],
        "refactor_pattern": [
            "Strangler Fig obligatorio",
            "Ejecución en paralelo ≥ 2 ciclos de cierre",
            "Corte incremental por módulo · sin big-bang",
        ],
        "coverage": ["Una prueba por regla de negocio · paridad contra el sistema heredado"],
        "gates": ["Simulacro de DR antes del corte", "SAST + SCA + imagen + IaC sin CRITICAL/HIGH"],
        "rto_rpo": ["RTO ≤ 15 min · RPO ≤ 5 min"],
        "duration": ["20-25 semanas"],
    },
    "T1": {
        "compute": ["Contenedores o serverless (sin VM)"],
        "edge": ["CDN + WAF"],
        "secrets": ["Llave KMS + gestor de secretos"],
        "refactor_pattern": ["Refactor directo con ejecución en paralelo acotada"],
        "coverage": ["Una prueba por regla de negocio"],
        "gates": ["SAST + SCA + imagen + IaC sin CRITICAL/HIGH"],
        "rto_rpo": ["RTO ≤ 1 h · RPO ≤ 15 min"],
        "duration": ["11-14 semanas"],
    },
    "T2": {
        "compute": ["Contenedores en una región multizona"],
        "edge": ["WAF si el endpoint es público · intranet no lo requiere"],
        "secrets": ["Llave KMS compartida admitida + gestor de secretos"],
        "refactor_pattern": ["Refactor directo", "Pruebas de humo + camino feliz"],
        "coverage": ["Reglas críticas con prueba"],
        "gates": ["SAST + SCA sin CRITICAL"],
        "rto_rpo": ["RTO ≤ 8 h · RPO ≤ 1 día"],
        "duration": ["11-14 semanas"],
    },
    "T3": {
        "compute": ["Batch programado en una zona"],
        "edge": ["Sin CDN si es sólo intranet"],
        "secrets": ["Llave KMS compartida admitida"],
        "refactor_pattern": ["Refactor directo o replatform"],
        "coverage": ["Pruebas de humo"],
        "gates": ["SCA sin CRITICAL"],
        "rto_rpo": ["RTO ≤ 1 día · RPO ≤ 3 días"],
        "duration": ["8-10 semanas"],
    },
}


# ════════════════════════════════════════════════════════════════════
# Bloqueantes transversales (ficticios)
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
        title="Sin ambientes de desarrollo y QA",
        description="Las aplicaciones heredadas sólo tienen producción: no hay dónde probar el refactor.",
        impact="TODAS · precede la fase 2",
        owner="Equipo de Plataforma Cloud",
        deadline="2026-12-15",
        status="open",
    ),
    CrossAppBlocker(
        blocker_id="B-ACCT",
        title="Cuentas cloud del programa",
        description="Preceden la red, las llaves, los roles y los pipelines.",
        impact="TODAS · arranque de la fase 2",
        owner="Equipo de Plataforma Cloud",
        deadline="2026-12-15",
        status="open",
    ),
    CrossAppBlocker(
        blocker_id="B-KMS",
        title="Llaves KMS por servicio",
        description="Las apps T0 y T1 necesitan una llave administrada por el cliente por servicio.",
        impact="T0 + T1",
        owner="Administración de llaves",
        deadline="2027-01-10",
        status="open",
    ),
    CrossAppBlocker(
        blocker_id="B-CI",
        title="Ejecutor de CI con acceso a la red interna",
        description="Las pruebas de integración contra bases heredadas no corren desde ejecutores públicos.",
        impact="Apps con base de datos heredada",
        owner="Equipo de Plataforma Cloud",
        deadline="2027-01-10",
        status="open",
    ),
]


# ════════════════════════════════════════════════════════════════════
# Fase 1 · entregables
# ════════════════════════════════════════════════════════════════════
PHASE1_DELIVERABLES: List[Dict[str, str]] = [
    {"num": "01", "file": "01_code_scan.md", "title": "Code Scan",
     "desc": "Escaneo AIOS · hallazgos por severidad"},
    {"num": "02", "file": "02_hallazgos_mapped.md", "title": "Hallazgos Consolidados",
     "desc": "Cruce de evaluación externa + talleres + escaneo propio · mapeo a CWE"},
    {"num": "03", "file": "03_arq_as_is.md", "title": "Arquitectura AS-IS",
     "desc": "Topología + stack + integraciones + volumetría"},
    {"num": "04", "file": "04_stakeholders.md", "title": "Stakeholders",
     "desc": "Dueños funcional y técnico + gobierno transversal"},
    {"num": "05", "file": "05_vulns.md", "title": "Vulnerabilidades y Compliance",
     "desc": "Detalle de vulnerabilidades + marcos aplicables + línea base de seguridad"},
    {"num": "06", "file": "06_deps.md", "title": "Dependencias",
     "desc": "Stack + integraciones externas + versión objetivo"},
    {"num": "07", "file": "07_preguntas_nuevas.md", "title": "Preguntas Pendientes",
     "desc": "Bloqueadoras + categorizadas por dominio"},
    {"num": "08", "file": "08_bloqueadores.md", "title": "Bloqueadores Fase 1",
     "desc": "Bloqueos absolutos + estado de mitigación"},
    {"num": "09", "file": "09_risk_register.md", "title": "Risk Register Inicial",
     "desc": "Riesgos por probabilidad × impacto"},
]


def get_app(key: str) -> AppMetadata | None:
    """Retorna la metadata de una aplicación por llave (sin distinguir mayúsculas)."""
    key_norm = key.lower().replace("-", "_").replace(" ", "_")
    return APPS.get(key_norm)


def list_apps_by_tier(tier: str) -> List[AppMetadata]:
    """Retorna las aplicaciones de un TIER."""
    return [app for app in APPS.values() if app.tier == tier.upper()]


def patterns_for_tier(tier: str) -> Dict[str, List[str]]:
    """Retorna los patrones obligatorios del TIER."""
    return TIER_PATTERNS.get(tier.upper(), {})


def get_cross_app_blockers(status: str | None = None) -> List[CrossAppBlocker]:
    """Retorna los bloqueantes transversales · filtra por status si se indica."""
    if status is None:
        return CROSS_APP_BLOCKERS
    return [b for b in CROSS_APP_BLOCKERS if b.status == status]
