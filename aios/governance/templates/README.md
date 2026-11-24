# Plantillas de `aios governance request`

Plantillas Jinja2 que producen la solicitud en Markdown (y en PDF si `weasyprint` y `markdown` están
instalados). Los datos salen de `aios/governance/rules/*.yaml`; los que trae el repositorio describen a
**Acme Corp, una organización ficticia**.

| Plantilla | Tipo de solicitud (`--type`) |
|---|---|
| `bd-access.j2` | `bd-access` · lectura de una base de datos heredada |
| `aws-account.j2` | `aws-account`, `aws-account-dedicated`, `aws-account-shared` |
| `cmk-request.j2` | `cmk-request` · llaves KMS administradas por el cliente |
| `hardware-key-request.j2` | `hardware-key` · llave de seguridad física para el perfil admin |
| `mailing-list.j2` | `mailing-list` · alta del equipo en la lista de distribución de la plataforma |
| `escalation-email.j2` | correo de `aios governance escalate` |

Variables comunes: `app`, `app_display`, `tier`, `request_id`, `request_date`, `requester` (nombre, correo,
rol) y `approval_chain` (pasos de la cadena que aplica a ese tipo de recurso). Cada constructor de
contexto está en `aios/governance/request_engine.py` (`ContextBuilder.for_*`).
