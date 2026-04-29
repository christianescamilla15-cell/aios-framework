# AIOS Governance Templates · Jinja2

Templates para `aios governance request` · generan PDF + Markdown formal de solicitudes.

## Templates disponibles (v3.8.0 F1 Día 2 · skeletons)

| Template | Tipo de recurso | Status |
|---|---|---|
| `bd-access.j2` | Acceso a base de datos legacy | skeleton |
| `aws-account.j2` | Creación cuenta AWS dedicada/compartida | skeleton |
| `cmk-request.j2` | Solicitud 5 CMKs umbrella vía GateOne | skeleton |
| `yubikey-request.j2` | Solicitud YubiKey física Admin | skeleton |
| `dl-inclusion.j2` | Inclusión DL amcssolutionarchitects | skeleton |

## Variables comunes a todos los templates

```python
{
    "app": "sicofav",                        # Nombre del aplicativo
    "app_display": "SICOFAV",                # Display name
    "app_id": "01",                          # Numeración 01-10
    "tier": "T0",                            # Tier asignado
    "requester": {
        "name": "Christian Hernández Escamilla",
        "email": "chernandeze@aeromexico.com",
        "role": "Líder técnico SICOFAV (eTribe)",
    },
    "co_requester": {                        # Para BD-access · Read Only
        "name": "Víctor Hugo Araiza",
        "email": "varaiza@aeromexico.com",
    },
    "approval_chain": [                      # 5 firmas en cadena
        {"step": 1, "role": "PM", "name": "Luis Ertuche"},
        # ...
    ],
    "request_date": "2026-04-28",
    "valid_for_days": 30,
    "request_id": "GOV-SICOFAV-BD-20260428-001",  # ID único · audit trail
    "context": "...",                        # Contexto técnico
    "compliance_commitments": [...],         # LFPDPPP/SOX/PCI commitments
}
```

## Implementación · F2 Día 4 (02-may)

```python
from jinja2 import Environment, FileSystemLoader
from pathlib import Path

env = Environment(
    loader=FileSystemLoader(Path(__file__).parent),
    autoescape=False,  # Markdown · no HTML
)

template = env.get_template("bd-access.j2")
markdown = template.render(**context)

# Render PDF con weasyprint via Markdown → HTML → PDF
```

## Equivalencia con templates manuales (referencia)

Cada template Jinja2 es la versión generative de un PDF que ya armé manualmente:

- `bd-access.j2` ≡ `Caso_Uso_SICOFAV_Acceso_BD_28abr.pdf`
- `aws-account.j2` ≡ Email-tipo de Plan_Gestion_Admin_Week1 (Acción 5)
- `cmk-request.j2` ≡ ticket umbrella GateOne (mencionado en Sprint Plan)
- `yubikey-request.j2` ≡ Email-tipo Plan_Gestion_Admin_Week1 (Acción 1)
- `dl-inclusion.j2` ≡ Email-tipo Plan_Gestion_Admin_Week1 (Acción 4)

## Templates futuros · v3.9.0+

- `iam-role.j2` · creación IAM role AMX-R-{App}-{tipo}
- `vpc-cidr.j2` · asignación CIDR + creación VPC
- `adr-signature.j2` · solicitud firma ADR (Borde Arq)
- `tier-reclassification.j2` · Re-clasificación TIER (caso SRG)
- `custodia-external.j2` · solicitud a DxC · Miatech · ATOS Lima
- `scope-change.j2` · cambio de scope del programa
