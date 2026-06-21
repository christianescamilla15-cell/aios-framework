"""AIOS Governance · EscalationEngine · genera correo formal de escalación slippage.

F2 Día 6 · usa AuditTrail.detect_slippage() (Día 5) + render Jinja2/PDF (mismo patrón
que RequestEngine en request_engine.py · F2 Día 4).

Auto-routing por severidad (vs approvals.yaml.slippage_thresholds.escalation_targets):
  - warn        → Luis Ertuche (PM intermediación)
  - escalate    → Elías Tapia (sponsor único interno)
  - emergency   → Sponsor business (Víctor Araiza · Eloisa Sánchez · J.T.)

Cron-friendly: usar --auto en CLI · output JSON estable para ScheduledTrigger.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from .audit_trail import AuditState, AuditTrail, default_audit_path, generate_request_id
from .loader import GovernanceRules


TEMPLATES_DIR = Path(__file__).parent / "templates"
ESCALATION_TEMPLATE = "escalation-email.j2"


@dataclass
class EscalationArtifacts:
    """Output completo de una escalación generada."""
    severity: str  # "warn" | "escalate" | "emergency"
    slippage_count: int
    markdown_path: Path | None
    pdf_path: Path | None
    audit_entry_recorded: bool
    escalation_to: dict[str, str]
    request_id: str  # ID de la entry de audit que registra la escalación
    slippages: list[dict[str, Any]]


class EscalationEngine:
    """Detecta slippage + genera correo MD+PDF + registra audit entry."""

    # Severidad → orden ascendente · usado para "tomar la peor"
    SEVERITY_ORDER = {"warn": 1, "escalate": 2, "emergency": 3}

    # Routing default · sobreescribible por flag --to en CLI
    SEVERITY_ROUTING = {
        "warn": {
            "name": "Luis Ertuche",
            "email": "luisertuche@acmeair.com",
            "role": "PM intermediación · Finance Operations",
            "key": "luis",
        },
        "escalate": {
            "name": "Elías Tapia",
            "email": "etapia@acmeair.com",
            "role": "Sponsor único interno ACME · Finance Operations",
            "key": "elias",
        },
        "emergency": {
            "name": "Víctor Araiza · Eloisa Sánchez · J.T.",
            "email": "varaiza@acmeair.com",
            "role": "Sponsor business · CC Cumplimiento + Negocio",
            "key": "sponsor",
        },
    }

    # Override manual · `--to <key>`
    MANUAL_ROUTING = {
        "luis": SEVERITY_ROUTING["warn"],
        "elias": SEVERITY_ROUTING["escalate"],
        "sponsor": SEVERITY_ROUTING["emergency"],
        "miguel-rachid": {
            "name": "Miguel Rachid",
            "email": "[pending confirmar]",
            "role": "Gerente Ciberseguridad ACME",
            "key": "miguel-rachid",
        },
        "victor": {
            "name": "Víctor Araiza",
            "email": "varaiza@acmeair.com",
            "role": "Sponsor IT · eTribe",
            "key": "victor",
        },
    }

    def __init__(self, rules: GovernanceRules):
        self._rules = rules
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            keep_trailing_newline=True,
            autoescape=False,
        )

    # -----------------------------------------------------------------------
    # API pública
    # -----------------------------------------------------------------------

    def detect(
        self,
        audit_root: Path,
        app: str | None = None,
        days_threshold: int | None = None,
    ) -> list[dict[str, Any]]:
        """Devuelve list de slippages detectados en el audit trail."""
        audit_path = default_audit_path(audit_root)
        if not audit_path.exists():
            return []

        thresholds = self._rules.approvals.get("slippage_thresholds", {})
        warn_d = thresholds.get("warn_after_days", 3)
        escalate_d = thresholds.get("escalate_after_days", 5)
        emergency_d = thresholds.get("emergency_after_days", 10)

        # --days-threshold puede bajar el "warn" · usado para forzar early scan
        if days_threshold is not None:
            warn_d = min(warn_d, days_threshold)

        trail = AuditTrail(audit_path)
        return trail.detect_slippage(
            warn_after_days=warn_d,
            escalate_after_days=escalate_d,
            emergency_after_days=emergency_d,
            app=app,
        )

    def generate(
        self,
        audit_root: Path,
        output_dir: Path,
        app: str | None = None,
        manual_to: str | None = None,
        days_threshold: int | None = None,
        write_pdf: bool = True,
        record_audit: bool = True,
        requester_email: str = "engineer@acmeair.com",
    ) -> EscalationArtifacts | None:
        """Detecta slippages + genera correo + registra audit entry.

        Returns None si no hay slippages que escalar.
        """
        slippages = self.detect(audit_root=audit_root, app=app, days_threshold=days_threshold)
        if not slippages:
            return None

        # 1 · Determinar severidad final · "tomar la peor"
        worst_severity = self._worst_severity(slippages)

        # 2 · Determinar destinatario
        if manual_to and manual_to != "auto":
            if manual_to not in self.MANUAL_ROUTING:
                raise ValueError(
                    f"--to '{manual_to}' inválido. Opciones: {sorted(self.MANUAL_ROUTING.keys())} | auto"
                )
            target = self.MANUAL_ROUTING[manual_to]
        else:
            target = self.SEVERITY_ROUTING[worst_severity]

        # 3 · Resolver requester desde stakeholders
        requester = self._resolve_requester(requester_email)

        # 4 · Construir contexto Jinja2
        context = self._build_context(
            slippages=slippages,
            worst_severity=worst_severity,
            target=target,
            requester=requester,
            app_filter=app,
        )

        # 5 · Render Markdown
        template = self._env.get_template(ESCALATION_TEMPLATE)
        markdown = template.render(**context)

        # 6 · Persistir output · request_id incluye HHMMSS para evitar colisiones
        # cuando se corre escalate múltiples veces en el mismo día (cron + manual)
        output_dir.mkdir(parents=True, exist_ok=True)
        now_utc = datetime.now(timezone.utc)
        date_str = now_utc.strftime("%Y%m%d")
        seq = int(now_utc.strftime("%H%M%S"))
        app_tag = (app or "all").upper()
        request_id = f"GOV-{app_tag}-ESC-{date_str}-{seq:06d}"

        md_path = output_dir / f"{request_id}_{worst_severity}.md"
        md_path.write_text(markdown, encoding="utf-8")

        # 7 · Generar PDF
        pdf_path: Path | None = None
        if write_pdf:
            try:
                pdf_path = self._render_pdf(
                    markdown,
                    output_dir / f"{request_id}_{worst_severity}.pdf",
                )
            except Exception as e:
                pdf_path = None
                import sys
                sys.stderr.write(f"⚠ PDF generation skipped: {type(e).__name__}: {e}\n")

        # 8 · Registrar entry en audit trail (SHA chain)
        audit_recorded = False
        if record_audit:
            audit_path = default_audit_path(audit_root)
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            trail = AuditTrail(audit_path)
            try:
                trail.append_entry(
                    request_id=request_id,
                    app=app or "ALL",
                    resource_type="escalation",
                    requested_by=requester["email"],
                    state_to=AuditState.REQUESTED,
                    actor=requester["email"],
                    actor_role="system",
                    action="escalation_sent",
                    notes=(
                        f"Auto-escalation severity={worst_severity} · "
                        f"{len(slippages)} slippages · to={target['email']}"
                    ),
                    metadata={
                        "severity": worst_severity,
                        "escalation_to": target["email"],
                        "escalation_to_name": target["name"],
                        "slippage_request_ids": [s["request_id"] for s in slippages],
                        "generated_by": "aios governance escalate v3.8.0",
                    },
                )
                audit_recorded = True
            except Exception as e:
                import sys
                sys.stderr.write(f"⚠ Audit entry skipped: {type(e).__name__}: {e}\n")

        return EscalationArtifacts(
            severity=worst_severity,
            slippage_count=len(slippages),
            markdown_path=md_path,
            pdf_path=pdf_path,
            audit_entry_recorded=audit_recorded,
            escalation_to=target,
            request_id=request_id,
            slippages=slippages,
        )

    # -----------------------------------------------------------------------
    # Helpers privados
    # -----------------------------------------------------------------------

    def _worst_severity(self, slippages: list[dict[str, Any]]) -> str:
        worst = "warn"
        for s in slippages:
            sev = s.get("severity", "warn")
            if self.SEVERITY_ORDER.get(sev, 0) > self.SEVERITY_ORDER[worst]:
                worst = sev
        return worst

    def _resolve_requester(self, email: str) -> dict[str, str]:
        team = self._rules.stakeholders.get("etribe_team", [])
        for m in team:
            if m.get("email", "").lower() == email.lower():
                return {
                    "name": m["name"],
                    "email": m["email"],
                    "role": m.get("role_etribe", "Líder técnico (eTribe)"),
                }
        # Fallback admin
        admin = next(
            (m for m in team if m.get("iam_profile") == "A"),
            {"name": "Christian Hernández Escamilla",
             "email": "engineer@acmeair.com",
             "role_etribe": "Líder técnico · Admin programa"},
        )
        return {
            "name": admin["name"],
            "email": admin["email"],
            "role": admin.get("role_etribe", "Líder técnico (eTribe)"),
        }

    def _build_context(
        self,
        slippages: list[dict[str, Any]],
        worst_severity: str,
        target: dict[str, str],
        requester: dict[str, str],
        app_filter: str | None,
    ) -> dict[str, Any]:
        thresholds = self._rules.approvals.get("slippage_thresholds", {})
        return {
            "severity": worst_severity,
            "severity_label": {
                "warn": "Aviso temprano",
                "escalate": "Escalación",
                "emergency": "Emergencia · cronograma en riesgo",
            }[worst_severity],
            "escalation_to": target,
            "slippages": slippages,
            "thresholds": {
                "warn": thresholds.get("warn_after_days", 3),
                "escalate": thresholds.get("escalate_after_days", 5),
                "emergency": thresholds.get("emergency_after_days", 10),
            },
            "app_filter": app_filter,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M %Z").strip(),
            "requester": requester,
            "cc_recipients": [
                "Víctor Araiza (Sponsor IT eTribe)",
                "Christian Hernández (Admin eTribe)",
                "Audit trail SHA256 chain",
            ],
            "commitments": [
                "Toda escalación queda registrada en `.aios/governance/audit-trail.jsonl` con hash chain SHA256 verificable",
                "Recordatorios automáticos según umbrales de `approvals.yaml`",
                "Escalación a sponsor business sólo en severity=emergency",
                "Cero spam: una sola escalación por solicitud por nivel de severidad",
            ],
        }

    def _render_pdf(self, markdown: str, output_path: Path) -> Path:
        """Convierte Markdown → HTML → PDF · mismo CSS que RequestEngine."""
        import markdown as md_lib
        from weasyprint import HTML, CSS

        html_body = md_lib.markdown(
            markdown,
            extensions=["tables", "fenced_code", "nl2br"],
        )
        html_doc = (
            "<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'></head>"
            f"<body>{html_body}</body></html>"
        )
        css = CSS(string="""
            @page { size: Letter; margin: 1.5cm; }
            body { font-family: Arial, sans-serif; font-size: 10pt; line-height: 1.4; color: #1a1a1a; }
            h1 { color: #b51717; font-size: 14pt; border-bottom: 2px solid #b51717; padding-bottom: 4px; }
            h2 { color: #0b3d91; font-size: 12pt; margin-top: 14px; }
            h3 { color: #0b3d91; font-size: 11pt; }
            table { border-collapse: collapse; width: 100%; font-size: 9pt; margin: 6px 0; }
            th, td { border: 1px solid #c8d0dc; padding: 4px 6px; text-align: left; vertical-align: top; }
            th { background: #fde8e8; color: #b51717; }
            code { background: #eef2f8; padding: 0 4px; border-radius: 2px; font-family: monospace; }
            ul, ol { margin: 4px 0 6px 22px; }
            hr { border: none; border-top: 1px dashed #c8d0dc; margin: 10px 0; }
            strong { color: #b51717; }
        """)
        HTML(string=html_doc).write_pdf(str(output_path), stylesheets=[css])
        return output_path
