"""
AMX Revenue Accounting · constraints adicionales derivados de retro arquitectos 20-abr-2026.

Aplica restricciones descubiertas en las sesiones con:
- Antonio Hernández Oropeza (arquitecto AWS AMX)
- Pedro Emmanuel Abaonza (arquitecto AMX)
- Israel Miguel González Sandoval (principal Borde de Arquitectura)
- Martín Alexis Martínez Hernández (líder madurez DevOps/SRE)
- Rigoberto Texmayer Gaona (Corp Solutions · pipelines)
- Miguel Rachid (Gerente Ciberseguridad AMX)

Carga como módulo del policy amx-revenue-accounting · enriquece las reglas existentes.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional


# ---------------------------------------------------------------------------
# Servicios AWS prohibidos en AMX México
# ---------------------------------------------------------------------------
PROHIBITED_AWS_SERVICES = {
    "ECS": {
        "alternative": "EKS (Kubernetes)",
        "reason": "ECS is explicitly prohibited in AMX Mexico per retro 20-abr-2026 (Antonio)",
        "severity": "CRITICAL",
    },
    "SES": {
        "alternative": "Relay interno AMX",
        "reason": "SES prohibited for transactional email · use AMX internal relay",
        "severity": "HIGH",
    },
    "SNS_FOR_EMAIL": {
        "alternative": "Relay interno AMX",
        "reason": "SNS not allowed for email notifications · events-only use",
        "severity": "HIGH",
    },
}


# ---------------------------------------------------------------------------
# Reglas KMS · una por servicio
# ---------------------------------------------------------------------------
KMS_RULES = {
    "one_key_per_service": True,
    "no_shared_cmk": True,
    "provisioning_channels": ["GateOne portal autoservicio", "AMX Chat Service Desk"],
    "requires": [
        "correo_visto_bueno_lider_amx_previo",
        "captura_correo_adjunta_ticket",
    ],
    "applied_via": "IaC (CloudFormation · CDK)",
}


# ---------------------------------------------------------------------------
# Roles IAM · prefijo amx-r-* enforced por SCPs
# ---------------------------------------------------------------------------
IAM_ROLE_RULES = {
    "required_prefix": "amx-r-",
    "enforced_by": "SCPs (Service Control Policies)",
    "two_principal_roles": {
        "ATR": {
            "requires": "YubiKey",
            "extra_privileges": True,
            "cannot_modify": ["KMS", "policies_organizacionales"],
        },
        "desarrollo": {
            "standard": True,
            "cannot_modify": ["KMS", "policies_organizacionales"],
        },
    },
}


# ---------------------------------------------------------------------------
# Secuencia de escaneos obligatoria pre-produccion
# ---------------------------------------------------------------------------
CYBER_SCAN_SEQUENCE = [
    {"tool": "WIZ", "scope": "AWS cloud posture", "order": 1},
    {"tool": "Veracode", "scope": "static code analysis", "order": 2},
    {"tool": "Prisma Cloud", "scope": "containers + compute", "order": 3},
    {"tool": "Tenable", "scope": "infrastructure as code", "order": 4},
]

CYBER_ACCEPTANCE_STANDARD = "practically no high/critical vulnerabilities"


# ---------------------------------------------------------------------------
# Gates pre-produccion · orden obligatorio
# ---------------------------------------------------------------------------
PRE_PROD_GATES = [
    {"id": 1, "gate": "óptimo · alta proyecto", "contact": "Carina"},
    {"id": 2, "gate": "Diagramas C4 en LeanIX", "contact": "Borde Arquitectura"},
    {"id": 3, "gate": "ADR con opción A vs B", "contact": "arq AMX"},
    {"id": 4, "gate": "Borde de Arquitectura aprobación", "contact": "Israel Miguel González Sandoval"},
    {"id": 5, "gate": "Cuenta AWS AMX", "contact": "Víctor Araiza (líder AMX)", "sla_hours": 24},
    {"id": 6, "gate": "VPC + subnets setup", "contact": "Diego Zarate"},
    {"id": 7, "gate": "KMS tickets (1 por servicio)", "contact": "Antonio H. Oropeza + líder AMX"},
    {"id": 8, "gate": "Escaneos CYBER (secuencia)", "contact": "Miguel Rachid + equipo CYBER"},
    {"id": 9, "gate": "Miguel Rachid gate final", "contact": "Miguel Rachid"},
]

# Observación arquitectos eTrive (20-abr):
# Los gates están en orden de DISEÑO → INFRAESTRUCTURA → CYBER
# No pedir fierros (VPC, KMS) antes de tener diseño aprobado por Borde Arq


# ---------------------------------------------------------------------------
# Clasificacion Tier · arquitectura obligatoria
# ---------------------------------------------------------------------------
TIER_ARCHITECTURE = {
    "T0": {
        "description": "Misión crítica 24×7 · revenue direct",
        "mandatory_architecture": ["EKS (Kubernetes)", "Serverless (Lambda)"],
        "ec2_allowed": False,
    },
    "T1": {
        "description": "Apps satelitales críticas",
        "mandatory_architecture": ["EKS (Kubernetes)", "Serverless (Lambda)"],
        "ec2_allowed": False,
        "typical_apps": ["SICOFAV", "ARC", "BSP", "CFDIs", "NoShow"],
    },
    "T2": {
        "description": "Operación normal · menor criticidad",
        "mandatory_architecture": ["EC2", "EKS", "Serverless"],
        "ec2_allowed": True,
        "typical_apps": ["SRG", "Comisiones Directas (standby)", "Comisiones Indirectas (standby)"],
    },
}

TIERS_DOCUMENT_LOCATION = {
    "site": "Dynamo (Dynamics program internal site)",
    "access_contacts": ["Edgar Castillo", "Israel Miguel González Sandoval"],
}


# ---------------------------------------------------------------------------
# Plataformas AMX obligatorias
# ---------------------------------------------------------------------------
MANDATORY_AMX_PLATFORMS = {
    "óptimo": "project management registry",
    "LeanIX": "architecture C4 diagrams",
    "GitHub Enterprise": "single source of truth code (no GitLab · no Miatech on-prem)",
    "GateOne": "ticket self-service portal",
    "AMX Chat Service Desk": "alternative ticket portal",
    "ServiceNow CMDB": "Jira traceability · commit→release cycle",
    "Dynamo": "maturity documentation + TIERS doc",
}


# ---------------------------------------------------------------------------
# Proceso estándar de ticket AMX
# ---------------------------------------------------------------------------
AMX_TICKET_PROCESS = [
    "Líder AMX directo envía correo previo con visto bueno",
    "Levantar ticket en GateOne (o AMX Chat Service Desk)",
    "Adjuntar captura del correo como evidencia",
    "Esperar SLA (24h laborales para cuenta AWS)",
    "Recibir respuesta vía correo con ID del recurso",
]


# ---------------------------------------------------------------------------
# Validators · funciones de verificacion
# ---------------------------------------------------------------------------

def check_prohibited_service(service_name: str) -> Optional[dict]:
    """Check if a service is in the AMX prohibited list."""
    key = service_name.upper().replace(" ", "_")
    if key in PROHIBITED_AWS_SERVICES:
        return PROHIBITED_AWS_SERVICES[key]
    return None


def check_role_prefix(role_name: str) -> bool:
    """Check if IAM role name has the required amx-r- prefix."""
    return role_name.startswith(IAM_ROLE_RULES["required_prefix"])


def get_scan_order(tool_name: str) -> Optional[int]:
    """Return the execution order index for a CYBER scanner."""
    for scan in CYBER_SCAN_SEQUENCE:
        if scan["tool"].lower() == tool_name.lower():
            return scan["order"]
    return None


def get_tier_architecture(tier: str) -> Optional[dict]:
    """Return architecture rules for a given tier (T0/T1/T2)."""
    return TIER_ARCHITECTURE.get(tier.upper())


def validate_gate_order(completed_gates: List[int]) -> dict:
    """
    Validate that gates are being followed in order.
    Returns dict with 'valid', 'next_gate', 'missing'.
    """
    expected_ids = [g["id"] for g in PRE_PROD_GATES]
    missing = [i for i in expected_ids if i not in completed_gates]
    if not missing:
        return {"valid": True, "next_gate": None, "missing": []}
    return {
        "valid": len(completed_gates) == max(completed_gates) if completed_gates else False,
        "next_gate": missing[0],
        "next_gate_info": next(g for g in PRE_PROD_GATES if g["id"] == missing[0]),
        "missing": missing,
    }


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------
RETRO_METADATA = {
    "date": "2026-04-20",
    "sources": [
        "video 11:18 · retro Antonio",
        "video 13:03 · Alexis madurez",
        "video 13:31 · Rigo+Lalo+Lira+Ibrahim",
        "video 13:58 · cierre Kiro+TIERS",
    ],
    "attendees_key": [
        "Antonio Hernández Oropeza",
        "Pedro Emmanuel Abaonza",
        "Israel Miguel González Sandoval",
        "Martín Alexis Martínez Hernández",
        "Rigoberto Texmayer Gaona",
        "Miguel Rachid",
        "José Fernando Pérez Izquierdo",
        "Luis Fernando Lira Guzmán",
        "Alberto Ibrahim Pedraza Cáscar",
    ],
    "version": "1.0.0",
}
