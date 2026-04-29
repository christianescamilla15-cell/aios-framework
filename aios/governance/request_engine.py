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
    """Construye el dict de variables que cada template necesita."""

    def __init__(self, rules: GovernanceRules):
        self._rules = rules

    def for_bd_access(self, app: str, requester_email: str) -> dict[str, Any]:
        meta = self._rules.get_app_metadata(app)
        tier = meta["tier"].split()[0]
        tier_def = self._rules.get_tier_definition(tier)
        team = self._rules.stakeholders["etride_team"]
        admin = next((m for m in team if m["iam_profile"] == "A"), None)
        sl = next((m for m in team if m["iam_profile"] == "SL"), None)

        # Find requester in team
        requester = next((m for m in team if m["email"].lower() == requester_email.lower()), admin or team[0])

        return {
            "app": app,
            "app_id": meta.get("app_id", "??"),
            "app_display": meta["name"],
            "tier": tier,
            "tier_description": tier_def.get("description_es", ""),
            "tier_priority_label": "Mission Critical" if tier == "T0" else f"{tier} priority",
            "phase_current": "Fase 1 Discovery (cierre)",
            "phase_next": "Fase 2 Configuración + Block 4 P2 Domain",
            "requester": {
                "name": requester["name"],
                "email": requester["email"],
                "role": requester.get("role_etride", "Líder técnico (eTride)"),
            },
            "co_requester": ({
                "name": sl["name"],
                "email": sl["email"],
            } if sl else None),
            "for_recipients": [
                "DBA Custodio (Miatech / DxC / AMX TI según app)",
                "Luis Ertuche (PM)",
                "Eloisa Sánchez (Cumplimiento)",
            ],
            "cc_recipients": [
                "Israel Miguel González Sandoval (Borde Arq)",
                "Carlos Reyes (CYBER)",
            ],
            "request_date": datetime.now().strftime("%Y-%m-%d"),
            "valid_for_days": 30,
            "context": (
                f"{meta['name']} es el aplicativo {tier} del programa Revenue Accounting Modernization 2026. "
                f"Para arranque de Fase 2 + Block 4 Domain, el equipo eTride requiere acceso de lectura "
                "a la base de datos legacy con los datos enmascarados conforme a LFPDPPP."
            ),
            "resources": self._default_bd_resources(app),
            "team": [{
                "name": m["name"],
                "email": m["email"],
                "aws_role": m["role_aws"],
                "iam_profile": f"AMX-R-{app.upper()}-{m['iam_profile']}",
            } for m in team],
            "compliance_commitments": [
                "NO se descargarán datos PII sin enmascaramiento (RFCs · nombres · cards)",
                "Cifrado en tránsito (TLS 1.2+) y reposo · CMK propia",
                "Bitácora de accesos auditable · SOX-friendly",
                "Vencimiento del acceso 30 días naturales · revocación automática",
                "Rotación de credenciales al final del periodo",
            ],
            "environments_count": 3,
            "cmk_count": tier_def.get("cmk_count", 5),
            "cmk_list": [
                {"scope": "secrets", "purpose": "Secrets Manager"},
                {"scope": "aurora", "purpose": "RDS Aurora encryption at rest"},
                {"scope": "s3-cfdis", "purpose": "S3 · COMPLIANCE 7y SAT"},
                {"scope": "logs", "purpose": "CloudWatch Logs"},
                {"scope": "ebs", "purpose": "EBS / Fargate"},
            ],
            "multiregion_required": tier_def.get("multiregion_required", False),
            "approval_chain": self._approval_chain_for("bd_legacy_access"),
            "blocking_block": "Block 4 Parte 2 (CQRS · 67 SPs migration)",
            "blocking_weeks": "2-3",
            "golive_target": meta.get("name", app) + " 11-sep-2026",
            "response_sla_days": 5,
        }

    def for_yubikey(self, app: str, requester_email: str) -> dict[str, Any]:
        team = self._rules.stakeholders["etride_team"]
        admin = next((m for m in team if m["iam_profile"] == "A"), None)
        if not admin:
            raise ValueError("No hay administrador en equipo eTride · ver stakeholders.yaml")

        aws_model = self._rules.tiers["aws_account_model"]
        tier_dist = (
            f"{len(aws_model['dedicated'])} cuentas dedicadas T0/T1 + "
            f"{len(aws_model['shared'])} cuenta T2 compartida"
        )

        return {
            "app": app,
            "request_date": datetime.now().strftime("%Y-%m-%d"),
            "request_id": "",  # filled by engine
            "requester": {
                "name": admin["name"],
                "email": admin["email"],
                "role": admin.get("role_etride", "Líder técnico"),
            },
            "total_aws_accounts": aws_model["total_aws_accounts"],
            "total_apps": len(self._rules.supported_apps),
            "tier_distribution": tier_dist,
            "aws_accounts_breakdown": (
                f"{len(aws_model['dedicated']) * aws_model['environments_per_account']} dedicadas + "
                f"{len(aws_model['shared']) * aws_model['environments_per_account']} compartida"
            ),
            "team_backup": [m["name"] for m in team if m["iam_profile"] == "DES"],
            "justification_reasons": [
                "Programa Revenue Accounting modernización 2026 · target go-live 11-sep",
                f"Admin único de las {aws_model['total_aws_accounts']} cuentas AWS del programa",
                "Corresponsabilidad firmada con Luis Ertuche (PM consultoría)",
            ],
            "custody_commitments": [
                "Llave física en custodia personal exclusiva",
                "NO compartir bajo ninguna circunstancia",
                "Reportar pérdida o sospecha de compromiso a CYBER en menos 1h",
                "Validación mensual de funcionamiento en las cuentas",
                "Devolución a CYBER al término del programa o cambio de rol",
            ],
            "attachment_filename": "Caso_Uso_SICOFAV_Acceso_BD_28abr.pdf",
        }

    def for_dl_inclusion(self, app: str, requester_email: str) -> dict[str, Any]:
        team = self._rules.stakeholders["etride_team"]
        admin = next((m for m in team if m["iam_profile"] == "A"), team[0])
        amx = self._rules.stakeholders["amx_stakeholders"]
        # Find Solution Architect lead
        sa_lead = next(
            (s for s in amx if "Solution Architect lead" in str(s.get("role", ""))),
            {"name": "Jose Fernando Pérez Izquierdo", "email": "jlperezi@aeromexico.com", "aliases": ["Fer"]},
        )

        return {
            "app": app,
            "request_date": datetime.now().strftime("%Y-%m-%d"),
            "request_id": "",  # filled by engine
            "recipient": {
                "name": sa_lead["name"],
                "email": sa_lead["email"],
                "short_name": (sa_lead.get("aliases", ["Fer"])[0]
                               if sa_lead.get("aliases") else "Fer"),
            },
            "reference_session_date": "27-abr-2026 03:30 PM",
            "team": [{
                "name": m["name"],
                "email": m["email"],
                "role_short": m["iam_profile"],
            } for m in team],
            "total_apps": len(self._rules.supported_apps),
            "time_savings_days": 10,
            "requester": {
                "name": admin["name"],
                "email": admin["email"],
                "role": admin.get("role_etride", "Líder técnico"),
            },
        }

    def for_aws_account(self, app: str, requester_email: str) -> dict[str, Any]:
        meta = self._rules.get_app_metadata(app)
        tier = meta["tier"].split()[0]
        tier_def = self._rules.get_tier_definition(tier)

        amx = self._rules.stakeholders["amx_stakeholders"]
        operator = next(
            (s for s in amx if "Admin entrega cuentas" in str(s.get("role", ""))),
            {"name": "Juan Carlos Vázquez Lorenzo", "email": "juancarlosvazquez@aeromexico.com",
             "short_name": "Juan Carlos"},
        )

        team = self._rules.stakeholders["etride_team"]
        admin = next((m for m in team if m["iam_profile"] == "A"), team[0])

        is_shared = tier == "T2"
        return {
            "app": app,
            "app_display": meta["name"],
            "tier": tier,
            "tier_priority_label": "Mission Critical" if tier == "T0" else "Strategic",
            "request_date": datetime.now().strftime("%Y-%m-%d"),
            "request_id": "",
            "operator": {
                "email": operator["email"],
                "short_name": operator.get("aliases", ["Juan Carlos"])[0]
                              if operator.get("aliases") else "Juan Carlos",
            },
            "reference_session_date": "27-abr-2026 03:30 PM",
            "account_type": "compartida (T2 hasta 6 apps)" if is_shared else "dedicada",
            "environments_count": 3,
            "environments": [
                {"name": f"amx-revacc-{app}-des", "description": "Desarrollo · sandbox interno eTride",
                 "short": "des"},
                {"name": f"amx-revacc-{app}-qa", "description": "QA · ambiente de pruebas pre-prod",
                 "short": "qa"},
                {"name": f"amx-revacc-{app}-prod", "description": "Producción · go-live target",
                 "short": "prod"},
            ],
            "project_code": None,  # pending Luis Ertuche
            "dl_status": "en gestión con Fer",
            "yubikey_status": "en trámite con CYBER",
            "cmk_count": tier_def.get("cmk_count", 5),
            "multiregion_required": tier_def.get("multiregion_required", False),
            "apps_consolidated": (["srg", "asr", "noshow"] if is_shared else []),
            "tier_justification": meta.get("rationale", []),
            "attachment_filename": f"Caso_Uso_{app.upper()}_28abr.pdf",
            "requester": {
                "name": admin["name"],
                "email": admin["email"],
                "role": admin.get("role_etride", "Líder técnico"),
            },
        }

    def for_cmk(self, app: str, requester_email: str) -> dict[str, Any]:
        meta = self._rules.get_app_metadata(app)
        tier = meta["tier"].split()[0]
        tier_def = self._rules.get_tier_definition(tier)
        amx = self._rules.stakeholders["amx_stakeholders"]
        operator = next(
            (s for s in amx if "GateOne" in str(s.get("role", ""))),
            {"name": "Antonio Hernández Oropeza", "email": "[pending confirmar]"},
        )
        team = self._rules.stakeholders["etride_team"]
        admin = next((m for m in team if m["iam_profile"] == "A"), team[0])
        cmk_count_per_env = tier_def.get("cmk_count", 5)
        env_count = 3
        cmk_count = cmk_count_per_env * env_count

        return {
            "app": app,
            "app_display": meta["name"],
            "tier": tier,
            "request_date": datetime.now().strftime("%Y-%m-%d"),
            "request_id": "",
            "operator": {"email": operator["email"]},
            "cmk_count": cmk_count,
            "cmk_count_per_env": cmk_count_per_env,
            "environments_count": env_count,
            "environments": [
                {"name": "des", "short": "des"},
                {"name": "qa", "short": "qa"},
                {"name": "prod", "short": "prod"},
            ],
            "cmk_list": [
                {"alias_pattern": f"amx-kms-{app}-{{env}}-secrets", "purpose": "Secrets Manager",
                 "consumers": ["Secrets Manager", "Lambda execution roles"],
                 "rotation": "anual", "tag_deny": True},
                {"alias_pattern": f"amx-kms-{app}-{{env}}-aurora", "purpose": "Aurora MySQL 8 at-rest",
                 "consumers": ["Aurora cluster", "Backups", "Snapshots"],
                 "rotation": "anual", "tag_deny": True},
                {"alias_pattern": f"amx-kms-{app}-{{env}}-s3-cfdis", "purpose": "S3 CFDIs · COMPLIANCE 7y",
                 "consumers": ["S3 bucket CFDIs", "Object Lock"],
                 "rotation": "anual", "tag_deny": True},
                {"alias_pattern": f"amx-kms-{app}-{{env}}-logs", "purpose": "CloudWatch Logs",
                 "consumers": ["CloudWatch Logs", "Lambda log groups"],
                 "rotation": "anual", "tag_deny": True},
                {"alias_pattern": f"amx-kms-{app}-{{env}}-ebs", "purpose": "EBS volumes · Fargate",
                 "consumers": ["EBS at-rest", "Fargate task storage"],
                 "rotation": "anual", "tag_deny": True},
            ],
            "tier_justification": meta.get("rationale", []),
            "sla_days_estimated": cmk_count * 3,  # 2-3 días por CMK
            "requester": {
                "name": admin["name"],
                "email": admin["email"],
                "role": admin.get("role_etride", "Líder técnico"),
            },
        }

    # -----------------------------------------------------------------------
    # Helpers privados
    # -----------------------------------------------------------------------

    def _default_bd_resources(self, app: str) -> list[dict[str, str]]:
        if app == "noshow":
            return [
                {"name": "BD legacy NoShow",
                 "access_type": "Read-only",
                 "justification": "Dump LFPDPPP-masked + golden file framework"},
                {"name": "Schema completo + SPs",
                 "access_type": "Read-only · DDL export",
                 "justification": "Modelar entidades reales en EF Core 8"},
                {"name": "Dataset seed PNRs/no-shows",
                 "access_type": "Read · subconjunto",
                 "justification": "UAT + bug verification (DR-25 · DR-18)"},
            ]
        return [
            {"name": f"BD legacy {app.upper()} · MySQL 5.7",
             "access_type": "Read-only · usuario etride_refactor_ro",
             "justification": "Dump LFPDPPP-masked · tests + parallel run + golden file"},
            {"name": "Schema completo · CREATE TABLE · índices · triggers",
             "access_type": "Read-only · script SQL exportado",
             "justification": "Modelar entidades reales en EF Core 8 · resolver 0 FKs"},
            {"name": "Stored Procedures · código fuente",
             "access_type": "Read-only · DDL completo",
             "justification": "Audit migrate/deprecate/archive"},
            {"name": "Logs · SLOW_LOG · binlogs muestra (30 días)",
             "access_type": "Read-only",
             "justification": "Identificar SPs activos vs huérfanos · sizing Aurora"},
            {"name": f"Dataset seed (~100 fixtures · LFPDPPP-safe)",
             "access_type": "Read · subconjunto representativo",
             "justification": "UAT · onboarding devs · demos sin exposición datos reales"},
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
                    "name": step_def.get("name", step_def.get("name_template", "TBD")),
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
        "yubikey-request": "yubikey-request.j2",
        "cmk-request": "cmk-request.j2",
        "dl-inclusion": "dl-inclusion.j2",
    }

    BUILDER_BY_TYPE = {
        "bd-access": "for_bd_access",
        "aws-account": "for_aws_account",
        "aws-account-dedicated": "for_aws_account",
        "aws-account-shared": "for_aws_account",
        "yubikey-request": "for_yubikey",
        "cmk-request": "for_cmk",
        "dl-inclusion": "for_dl_inclusion",
    }

    def __init__(self, rules: GovernanceRules):
        self._rules = rules
        self._builder = ContextBuilder(rules)
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
        markdown = template.render(**context)

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
            metadata={"created_by": "aios governance request v3.8.0"},
        )
