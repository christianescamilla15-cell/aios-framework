"""AIOS Governance · RequestEngine · genera PDF formal de solicitudes.

Carga contexto desde governance rules + parámetros usuario · renderiza templates Jinja2 ·
genera Markdown + PDF · crea entry inicial en audit trail (estado 'requested').
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .audit_trail import (
    AuditState,
    AuditTrail,
    default_audit_path,
    generate_request_id,
)
from .loader import GovernanceRules


TEMPLATES_DIR = Path(__file__).parent / "templates"


@dataclass
class RequestArtifacts:
    """Output completo de una request generation."""
    request_id: str
    markdown_path: Path
    pdf_path: Path | None
    audit_entry_recorded: bool
    template_used: str


# ---------------------------------------------------------------------------
# Context Builders · 1 por tipo de recurso
# ---------------------------------------------------------------------------

class ContextBuilder:
    """Construye el dict de variables que cada template necesita.

    Todo sale de los YAML de `aios/governance/rules/` (equipo, interesados, TIER y cadena de
    aprobaciones): el código no conoce personas ni organizaciones.
    """

    ENVIRONMENTS = ("dev", "qa", "prod")

    def __init__(self, rules: GovernanceRules):
        self._rules = rules

    # -- comunes ---------------------------------------------------------------

    @property
    def _organization(self) -> str:
        return self._rules.tiers.get("organization", "Organización")

    @property
    def _team(self) -> list[dict[str, Any]]:
        return self._rules.stakeholders.get("delivery_team", [])

    def _admin(self) -> dict[str, Any]:
        team = self._team
        return next((m for m in team if m.get("iam_profile") == "admin"), team[0])

    def _requester(self, requester_email: str) -> dict[str, str]:
        member = next(
            (m for m in self._team if m["email"].lower() == requester_email.lower()),
            self._admin(),
        )
        return {
            "name": member["name"],
            "email": member["email"],
            "role": member.get("role_team", "Equipo de entrega"),
        }

    def _org_contact(self, role_fragment: str) -> dict[str, str]:
        for s in self._rules.stakeholders.get("org_stakeholders", []):
            if role_fragment.lower() in str(s.get("role", "")).lower():
                return {"name": s["name"], "email": s["email"]}
        return {"name": role_fragment, "email": "(por confirmar)"}

    def _tier_of(self, app: str) -> tuple[dict[str, Any], str, dict[str, Any]]:
        meta = self._rules.get_app_metadata(app)
        tier = meta["tier"].split()[0]
        return meta, tier, self._rules.get_tier_definition(tier)

    @staticmethod
    def _priority_label(tier: str) -> str:
        return {"T0": "Crítica", "T1": "Estratégica", "T2": "Táctica", "T3": "De apoyo"}.get(tier, tier)

    def _cmk_count(self, tier_def: dict[str, Any]) -> int:
        return tier_def.get("cmk_count", tier_def.get("cmk_count_per_account", 5))

    # -- por tipo de recurso ---------------------------------------------------

    def for_bd_access(self, app: str, requester_email: str) -> dict[str, Any]:
        meta, tier, tier_def = self._tier_of(app)
        readonly = next((m for m in self._team if m.get("iam_profile") == "readonly"), None)
        chain = self._approval_chain_for("bd_legacy_access")
        return {
            "organization": self._organization,
            "app": app,
            "app_id": meta.get("app_id", "??"),
            "app_display": meta["name"],
            "tier": tier,
            "tier_description": tier_def.get("description_es", ""),
            "tier_priority_label": self._priority_label(tier),
            "requester": self._requester(requester_email),
            "co_requester": ({"name": readonly["name"], "email": readonly["email"]} if readonly else None),
            "for_recipients": [f"{s['name']} ({s['role']})" for s in chain[:2]],
            "cc_recipients": [f"{s['name']} ({s['role']})" for s in chain[2:]],
            "request_date": datetime.now().strftime("%Y-%m-%d"),
            "valid_for_days": 30,
            "context": (
                f"{meta['name']} es una aplicación {tier} en modernización. Para caracterizar su "
                "comportamiento actual el equipo necesita leer la base de datos heredada con los datos "
                "personales enmascarados."
            ),
            "resources": self._default_bd_resources(app),
            "team": [{
                "name": m["name"],
                "email": m["email"],
                "aws_role": m.get("role_aws", ""),
                "iam_profile": f"acme-role-{app}-{m['iam_profile']}",
            } for m in self._team],
            "compliance_commitments": [
                "No se extraen datos personales sin enmascarar",
                "Cifrado en tránsito (TLS 1.2+) y en reposo con llave propia",
                "Bitácora de accesos auditable",
                "El acceso vence a los 30 días naturales y se revoca solo",
                "Rotación de credenciales al cierre del periodo",
            ],
            "environments_count": len(self.ENVIRONMENTS),
            "cmk_count": self._cmk_count(tier_def),
            "cmk_list": [
                {"scope": "secrets", "purpose": "Gestor de secretos"},
                {"scope": "database", "purpose": "Base de datos en reposo y respaldos"},
                {"scope": "storage", "purpose": "Almacenamiento de objetos"},
                {"scope": "logs", "purpose": "Bitácoras"},
                {"scope": "volumes", "purpose": "Volúmenes de cómputo"},
            ],
            "multiregion_required": tier_def.get("multiregion_required", False),
            "approval_chain": chain,
            "blocking_block": "la fase de caracterización (pruebas de paridad contra el sistema heredado)",
            "response_sla_days": 5,
        }

    def for_hardware_key(self, app: str, requester_email: str) -> dict[str, Any]:
        admin = self._admin()
        if admin.get("iam_profile") != "admin":
            raise ValueError("No hay perfil admin en delivery_team · ver stakeholders.yaml")
        aws_model = self._rules.tiers["aws_account_model"]
        envs = aws_model["environments_per_account"]
        return {
            "organization": self._organization,
            "app": app,
            "request_date": datetime.now().strftime("%Y-%m-%d"),
            "request_id": "",  # lo llena el motor
            "requester": {
                "name": admin["name"],
                "email": admin["email"],
                "role": admin.get("role_team", "Líder técnico"),
            },
            "security_office": self._org_contact("seguridad"),
            "total_aws_accounts": aws_model["total_aws_accounts"],
            "total_apps": len(self._rules.supported_apps),
            "tier_distribution": (
                f"{len(aws_model['dedicated'])} cuentas dedicadas T0/T1 + "
                f"{len(aws_model['shared'])} compartida T2"
            ),
            "aws_accounts_breakdown": (
                f"{len(aws_model['dedicated']) * envs} dedicadas + "
                f"{len(aws_model['shared']) * envs} compartidas"
            ),
            "team_backup": [m["name"] for m in self._team if m.get("iam_profile") == "dev"],
            "justification_reasons": [
                f"Única persona con perfil admin en las {aws_model['total_aws_accounts']} cuentas del programa",
                "El perfil admin exige segundo factor físico (naming.yaml · profiles.admin)",
            ],
            "custody_commitments": [
                "Custodia personal y exclusiva de la llave",
                "No se comparte bajo ninguna circunstancia",
                "Pérdida o sospecha de compromiso se reporta en menos de 1 hora",
                "Devolución al terminar el programa o cambiar de rol",
            ],
            "approval_chain": self._approval_chain_for("hardware_key_request"),
        }

    def for_mailing_list(self, app: str, requester_email: str) -> dict[str, Any]:
        return {
            "organization": self._organization,
            "app": app,
            "request_date": datetime.now().strftime("%Y-%m-%d"),
            "request_id": "",  # lo llena el motor
            "recipient": self._org_contact("lista de distribución"),
            "team": [{
                "name": m["name"],
                "email": m["email"],
                "role_short": m["iam_profile"],
            } for m in self._team],
            "total_apps": len(self._rules.supported_apps),
            "requester": self._requester(requester_email),
            "approval_chain": self._approval_chain_for("mailing_list_inclusion"),
        }

    def for_aws_account(self, app: str, requester_email: str) -> dict[str, Any]:
        meta, tier, tier_def = self._tier_of(app)
        shared_accounts = self._rules.tiers.get("aws_account_model", {}).get("shared", [])
        consolidated = next(
            (s.get("apps_consolidated", []) for s in shared_accounts if app in s.get("apps_consolidated", [])),
            [],
        )
        is_shared = bool(tier_def.get("cuenta_aws_compartida"))
        max_apps = tier_def.get("cuenta_aws_compartida_max_apps", 1)
        chain_key = "aws_account_creation_tier_shared" if is_shared else "aws_account_creation_tier_dedicated"
        prefix = f"acme-shared-{tier.lower()}" if is_shared else f"acme-{app}"
        return {
            "organization": self._organization,
            "app": app,
            "app_display": meta["name"],
            "tier": tier,
            "tier_priority_label": self._priority_label(tier),
            "request_date": datetime.now().strftime("%Y-%m-%d"),
            "request_id": "",
            "operator": self._org_contact("cuentas cloud"),
            "account_type": f"compartida ({tier} hasta {max_apps} apps)" if is_shared else "dedicada",
            "environments": [
                {"name": f"{prefix}-dev", "description": "Desarrollo"},
                {"name": f"{prefix}-qa", "description": "Pruebas previas a producción"},
                {"name": f"{prefix}-prod", "description": "Producción"},
            ],
            "cmk_count": self._cmk_count(tier_def),
            "multiregion_required": tier_def.get("multiregion_required", False),
            "apps_consolidated": consolidated if is_shared else [],
            "tier_justification": meta.get("rationale", []),
            "requester": self._requester(requester_email),
            "approval_chain": self._approval_chain_for(chain_key),
        }

    def for_cmk(self, app: str, requester_email: str) -> dict[str, Any]:
        meta, tier, tier_def = self._tier_of(app)
        cmk_count_per_env = self._cmk_count(tier_def)
        env_count = len(self.ENVIRONMENTS)
        scopes = [
            ("secrets", "Gestor de secretos", ["Gestor de secretos", "Roles de ejecución"]),
            ("database", "Base de datos en reposo", ["Clúster de base de datos", "Respaldos", "Snapshots"]),
            ("storage", "Almacenamiento de objetos", ["Buckets de la app"]),
            ("logs", "Bitácoras", ["Grupos de bitácoras"]),
            ("volumes", "Volúmenes de cómputo", ["Volúmenes", "Almacenamiento de tareas"]),
        ]
        return {
            "organization": self._organization,
            "app": app,
            "app_display": meta["name"],
            "tier": tier,
            "request_date": datetime.now().strftime("%Y-%m-%d"),
            "request_id": "",
            "operator": self._org_contact("llaves kms"),
            "cmk_count": cmk_count_per_env * env_count,
            "cmk_count_per_env": cmk_count_per_env,
            "environments_count": env_count,
            "environments": [{"name": e} for e in self.ENVIRONMENTS],
            "cmk_list": [
                {"alias_pattern": f"acme-kms-{app}-{scope}", "purpose": purpose,
                 "consumers": consumers, "rotation": "anual", "tag_deny": True}
                for scope, purpose, consumers in scopes[:cmk_count_per_env]
            ],
            "tier_justification": meta.get("rationale", []),
            "sla_days_estimated": cmk_count_per_env * env_count,
            "requester": self._requester(requester_email),
            "approval_chain": self._approval_chain_for("cmk_request"),
        }

    # -----------------------------------------------------------------------
    # Helpers privados
    # -----------------------------------------------------------------------

    @staticmethod
    def _default_bd_resources(app: str) -> list[dict[str, str]]:
        return [
            {"name": f"Base de datos heredada de {app}",
             "access_type": "Sólo lectura · usuario dedicado",
             "justification": "Copia enmascarada para pruebas de paridad"},
            {"name": "Esquema completo (tablas, índices, disparadores)",
             "access_type": "Sólo lectura · DDL exportado",
             "justification": "Modelar las entidades reales"},
            {"name": "Procedimientos almacenados",
             "access_type": "Sólo lectura · código fuente",
             "justification": "Decidir qué se migra, qué se retira y qué se archiva"},
            {"name": "Muestra de datos (~100 registros enmascarados)",
             "access_type": "Lectura · subconjunto",
             "justification": "Casos de prueba y demostraciones sin datos reales"},
        ]

    def _approval_chain_for(self, chain_key: str) -> list[dict[str, str]]:
        chains = self._rules.approvals.get("approval_chains_by_resource", {})
        chain = chains.get(chain_key, {})
        required_steps = chain.get("required_steps", [1, 2, 3])
        all_steps = self._rules.approvals["approval_chain_default"]["steps"]

        result = []
        for step_def in all_steps:
            if step_def["step"] in required_steps:
                result.append({
                    "role": step_def.get("role", ""),
                    "name": step_def.get("name", "por definir"),
                    "action": step_def.get("validates", ""),
                })
        return result


# ---------------------------------------------------------------------------
# RequestEngine · core
# ---------------------------------------------------------------------------

class RequestEngine:
    """Genera artefactos de governance request (MD + PDF + audit entry)."""

    TEMPLATE_BY_TYPE = {
        "bd-access": "bd-access.j2",
        "aws-account": "aws-account.j2",
        "aws-account-dedicated": "aws-account.j2",
        "aws-account-shared": "aws-account.j2",
        "hardware-key": "hardware-key-request.j2",
        "cmk-request": "cmk-request.j2",
        "mailing-list": "mailing-list.j2",
    }

    BUILDER_BY_TYPE = {
        "bd-access": "for_bd_access",
        "aws-account": "for_aws_account",
        "aws-account-dedicated": "for_aws_account",
        "aws-account-shared": "for_aws_account",
        "hardware-key": "for_hardware_key",
        "cmk-request": "for_cmk",
        "mailing-list": "for_mailing_list",
    }

    def __init__(self, rules: GovernanceRules):
        self._rules = rules
        self._builder = ContextBuilder(rules)
        # Salida Markdown (no HTML servido): escapar HTML la corrompería. Las variables salen de los YAML
        # versionados del paquete, no de entrada de usuario; el PDF se arma desde ese Markdown.
        # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2 -- plantillas del paquete, salida Markdown
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            keep_trailing_newline=True,
            autoescape=False,
        )
        self._env.filters["upper"] = str.upper

    def generate(
        self,
        app: str,
        resource_type: str,
        output_dir: Path,
        requester_email: str,
        write_pdf: bool = True,
        record_audit: bool = True,
        audit_root: Path | None = None,
    ) -> RequestArtifacts:
        if resource_type not in self.TEMPLATE_BY_TYPE:
            raise ValueError(
                f"resource_type '{resource_type}' no soportado. "
                f"Opciones: {sorted(self.TEMPLATE_BY_TYPE.keys())}"
            )

        # 1 · Construir contexto
        builder_method = getattr(self._builder, self.BUILDER_BY_TYPE[resource_type])
        context = builder_method(app=app, requester_email=requester_email)

        # 2 · Generar request_id
        request_id = generate_request_id(resource_type=resource_type, app=app)
        context["request_id"] = request_id

        # 3 · Render markdown
        template_name = self.TEMPLATE_BY_TYPE[resource_type]
        template = self._env.get_template(template_name)
        markdown = template.render(**context)  # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2 --contexto construido desde los YAML

        # 4 · Persistir output_dir/{request_id}.md
        output_dir.mkdir(parents=True, exist_ok=True)
        md_path = output_dir / f"{request_id}.md"
        md_path.write_text(markdown, encoding="utf-8")

        # 5 · Generar PDF si se pide
        pdf_path: Path | None = None
        if write_pdf:
            try:
                pdf_path = self._render_pdf(markdown, output_dir / f"{request_id}.pdf")
            except Exception as e:  # PDF es nice-to-have · no falla si dependencias missing
                pdf_path = None
                import sys
                sys.stderr.write(f"⚠ PDF generation skipped: {type(e).__name__}: {e}\n")

        # 6 · Audit trail entry inicial (estado 'requested')
        audit_recorded = False
        if record_audit:
            audit_root = audit_root or Path.cwd()
            audit_path = default_audit_path(audit_root)
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            trail = AuditTrail(audit_path)
            try:
                self._append_initial_audit_entry(
                    trail=trail,
                    request_id=request_id,
                    app=app,
                    resource_type=resource_type,
                    requester=requester_email,
                )
                audit_recorded = True
            except Exception as e:  # graceful · audit puede fallar si jsonl corrupt
                import sys
                sys.stderr.write(f"⚠ Audit trail skipped: {type(e).__name__}: {e}\n")

        return RequestArtifacts(
            request_id=request_id,
            markdown_path=md_path,
            pdf_path=pdf_path,
            audit_entry_recorded=audit_recorded,
            template_used=template_name,
        )

    # -----------------------------------------------------------------------
    # Helpers privados
    # -----------------------------------------------------------------------

    def _render_pdf(self, markdown: str, output_path: Path) -> Path:
        """Convierte Markdown → HTML → PDF usando weasyprint."""
        import markdown as md_lib
        from weasyprint import HTML, CSS

        html_body = md_lib.markdown(
            markdown,
            extensions=["tables", "fenced_code", "nl2br"],
        )
        html_doc = self._wrap_html(html_body)
        css = CSS(string="""
            @page { size: Letter; margin: 1.5cm; }
            body { font-family: Arial, sans-serif; font-size: 10pt; line-height: 1.4; color: #1a1a1a; }
            h1 { color: #0b3d91; font-size: 14pt; border-bottom: 2px solid #0b3d91; padding-bottom: 4px; }
            h2 { color: #0b3d91; font-size: 12pt; margin-top: 14px; }
            h3 { color: #0b3d91; font-size: 11pt; }
            table { border-collapse: collapse; width: 100%; font-size: 9pt; margin: 6px 0; }
            th, td { border: 1px solid #c8d0dc; padding: 4px 6px; text-align: left; vertical-align: top; }
            th { background: #e8eef7; color: #0b3d91; }
            code { background: #eef2f8; padding: 0 4px; border-radius: 2px; font-family: monospace; }
            ul, ol { margin: 4px 0 6px 22px; }
            hr { border: none; border-top: 1px dashed #c8d0dc; margin: 10px 0; }
        """)
        HTML(string=html_doc).write_pdf(str(output_path), stylesheets=[css])
        return output_path

    @staticmethod
    def _wrap_html(body: str) -> str:
        return f"<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'></head><body>{body}</body></html>"

    @staticmethod
    def _append_initial_audit_entry(
        trail: AuditTrail,
        request_id: str,
        app: str,
        resource_type: str,
        requester: str,
    ) -> None:
        """Escribe entry inicial al audit trail · usa append_entry con SHA chain real (F2 Día 5)."""
        trail.append_entry(
            request_id=request_id,
            app=app,
            resource_type=resource_type,
            requested_by=requester,
            state_to=AuditState.REQUESTED,
            actor=requester,
            actor_role="requester",
            action="create",
            notes="Initial entry · auto-generated by RequestEngine",
            metadata={"created_by": "aios governance request"},
        )
