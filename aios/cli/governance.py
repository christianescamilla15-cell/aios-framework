"""AIOS Governance CLI · 4 subcomandos del módulo Governance Pack v3.8.0

Subcomandos expuestos vía aios CLI:
  aios governance check    --app <app>             · valida reglas AMX
  aios governance request  --type <type> --app ... · genera PDF formal
  aios governance audit    --app <app> [--update]  · audit trail 5 firmas
  aios governance escalate --app <app> --to <who>  · escalación slippage

Status: SKELETON · diseño v3.8.0 F1 Día 2 · 28-abr-2026
Implementación real: F2 Días 3-7
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Resource types · request templates
# ---------------------------------------------------------------------------

class ResourceType(str, Enum):
    """Tipos de recursos solicitables · matchea approvals.yaml chains_by_resource."""

    BD_LEGACY_ACCESS = "bd-access"
    AWS_ACCOUNT_DEDICATED = "aws-account-dedicated"
    AWS_ACCOUNT_SHARED = "aws-account-shared"
    CMK_REQUEST = "cmk-request"
    YUBIKEY_REQUEST = "yubikey-request"
    IAM_ROLE_CREATION = "iam-role"
    VPC_CIDR = "vpc-cidr"
    ADR_SIGNATURE = "adr-signature"
    TIER_RECLASSIFICATION = "tier-reclassification"
    CUSTODIA_EXTERNAL = "custodia-external"
    SCOPE_CHANGE = "scope-change"
    DL_INCLUSION = "dl-inclusion"


class CheckSeverity(str, Enum):
    """Severity para findings de governance check."""
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    CRITICAL = "CRITICAL"


@dataclass
class GovernanceFinding:
    """Resultado individual de governance check."""
    rule_id: str
    severity: CheckSeverity
    category: str  # 'tier' · 'naming' · 'approvals' · 'stakeholders'
    message: str
    location: str | None = None
    suggestion: str | None = None


@dataclass
class CheckReport:
    """Reporte consolidado de aios governance check."""
    app: str
    timestamp: datetime
    total_findings: int
    pass_count: int
    warn_count: int
    fail_count: int
    critical_count: int
    findings: list[GovernanceFinding]

    @property
    def is_passing(self) -> bool:
        return self.fail_count == 0 and self.critical_count == 0


# ---------------------------------------------------------------------------
# Subcommand 1 · governance check
# ---------------------------------------------------------------------------

def cmd_check(args: argparse.Namespace) -> int:
    """`aios governance check --app sicofav --root /path`

    Valida que el aplicativo cumple las reglas AMX:
      - TIER assignment correcto vs criterios oficiales (tiers.yaml)
      - Naming patterns (IAM · CMK · Secret · KMS-aws-managed prohibition)
      - Status de las 5 firmas en cadena (cuando aplica · audit-trail.jsonl)

    Returns:
        0 si todo PASS · 1 si hay WARN · 2 si hay FAIL · 3 si hay CRITICAL
    """
    from aios.governance.loader import load_rules
    from aios.governance.checkers import NamingChecker, TierChecker, ApprovalsChecker
    from aios.governance.formatters import format_text, format_json
    from aios.governance.models import CheckReport, CheckSeverity

    rules = load_rules()
    if args.app not in rules.supported_apps:
        sys.stderr.write(
            f"❌ App '{args.app}' no soportada. "
            f"Apps válidas: {', '.join(rules.supported_apps)}\n"
        )
        return 2

    root = Path(args.root).resolve()
    if not root.is_dir():
        sys.stderr.write(f"❌ Root path no es un directorio válido: {root}\n")
        return 2

    # Ejecutar 3 checkers
    report = CheckReport(app=args.app, timestamp=datetime.now())
    for checker_cls in (NamingChecker, TierChecker, ApprovalsChecker):
        checker = checker_cls(rules)
        try:
            findings = checker.check(root, args.app)
            report.findings.extend(findings)
        except Exception as e:
            sys.stderr.write(f"⚠ Checker {checker_cls.__name__} falló: {type(e).__name__}: {e}\n")

    # Output
    use_color = sys.stdout.isatty()
    if getattr(args, "format", "text") == "json":
        print(format_json(report))
    else:
        print(format_text(report, use_color=use_color))

    # Exit code
    if report.critical_count > 0:
        return 3
    if report.fail_count > 0:
        return 2
    if getattr(args, "strict", False) and report.warn_count > 0:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Subcommand 2 · governance request
# ---------------------------------------------------------------------------

def cmd_request(args: argparse.Namespace) -> int:
    """`aios governance request --type bd-access --app sicofav --requester chernandeze@aeromexico.com`

    Genera PDF + Markdown formal + audit trail entry inicial.

    Templates soportados v3.8.0 F2 Día 4:
      - bd-access · Caso de uso para acceso BD legacy
      - aws-account · Solicitud cuenta AWS dedicada/compartida
      - yubikey-request · Solicitud YubiKey física Admin
      - cmk-request · Solicitud 5 CMKs umbrella vía GateOne
      - dl-inclusion · Inclusión DL amcssolutionarchitects

    Returns:
        0 si genera correctamente · 1 si template no existe · 2 si app no existe
    """
    from aios.governance.loader import load_rules
    from aios.governance.request_engine import RequestEngine

    rules = load_rules()
    if args.app not in rules.supported_apps:
        sys.stderr.write(
            f"❌ App '{args.app}' no soportada. "
            f"Apps válidas: {', '.join(rules.supported_apps)}\n"
        )
        return 2

    requester_email = getattr(args, "requester", None)
    if not requester_email:
        # Default · admin del equipo eTribe
        team = rules.stakeholders["etribe_team"]
        admin = next((m for m in team if m["iam_profile"] == "A"), team[0])
        requester_email = admin["email"]

    output_dir = Path(args.output).resolve()
    audit_root = Path(getattr(args, "audit_root", ".")).resolve()

    engine = RequestEngine(rules)

    try:
        artifacts = engine.generate(
            app=args.app,
            resource_type=args.type,
            output_dir=output_dir,
            requester_email=requester_email,
            write_pdf=getattr(args, "format", "both") in ("pdf", "both"),
            record_audit=True,
            audit_root=audit_root,
        )
    except ValueError as e:
        sys.stderr.write(f"❌ {e}\n")
        return 1

    print("=" * 72)
    print(f"  AIOS Governance Request · {args.type} · {args.app}")
    print("=" * 72)
    print(f"  Request ID:  {artifacts.request_id}")
    print(f"  Template:    {artifacts.template_used}")
    print(f"  Markdown:    {artifacts.markdown_path}")
    if artifacts.pdf_path:
        print(f"  PDF:         {artifacts.pdf_path}")
    else:
        print(f"  PDF:         (skipped · weasyprint no disponible)")
    print(f"  Audit entry: {'✓ recorded' if artifacts.audit_entry_recorded else '✗ skipped'}")
    print("=" * 72)
    print()
    print("Próximos pasos · cadena de aprobaciones:")
    print(f"  1. Revisar y enviar el documento generado")
    print(f"  2. Esperar respuestas · seguir status con `aios governance audit --app {args.app}`")
    print(f"  3. Si hay slippage · ejecutar `aios governance escalate --app {args.app}`")
    return 0


# ---------------------------------------------------------------------------
# Subcommand 3 · governance audit
# ---------------------------------------------------------------------------

def cmd_audit(args: argparse.Namespace) -> int:
    """`aios governance audit --app sicofav [--update --signer "..." --status approved]`

    Modos:
      - Lectura (default): muestra tabla con estado actual de todas las solicitudes del app
      - Update (--update): registra una transición de estado (firma) en audit trail

    Returns:
        0 OK · 1 si transición inválida · 2 si app/request no existe · 3 si chain corrupta
    """
    from aios.governance.loader import load_rules
    from aios.governance.audit_trail import (
        AuditTrail,
        AuditState,
        default_audit_path,
    )

    rules = load_rules()
    if args.app not in rules.supported_apps:
        sys.stderr.write(
            f"❌ App '{args.app}' no soportada. "
            f"Apps válidas: {', '.join(rules.supported_apps)}\n"
        )
        return 2

    audit_root = Path(getattr(args, "audit_root", ".")).resolve()
    audit_path = default_audit_path(audit_root)
    trail = AuditTrail(audit_path)

    # ---- Modo update ----
    if getattr(args, "update", False):
        if not args.status:
            sys.stderr.write("❌ --update requiere --status (approved/rejected/in-review/...)\n")
            return 1
        if not args.signer:
            sys.stderr.write("❌ --update requiere --signer\n")
            return 1

        # Identificar request_id
        request_id = getattr(args, "request_id", None)
        if not request_id:
            # Usar la última request del app
            ids = trail.list_request_ids(app=args.app)
            if not ids:
                sys.stderr.write(f"❌ No hay solicitudes registradas para '{args.app}'\n")
                return 2
            request_id = ids[-1]
            print(f"  (usando request_id más reciente: {request_id})")

        # Buscar metadata de la request original
        existing = trail.list_entries(request_id=request_id)
        if not existing:
            sys.stderr.write(f"❌ Request '{request_id}' no encontrada\n")
            return 2

        first = existing[0]

        try:
            new_state = AuditState(args.status)
        except ValueError:
            sys.stderr.write(
                f"❌ Status '{args.status}' inválido. "
                f"Valores: {[s.value for s in AuditState]}\n"
            )
            return 1

        try:
            entry = trail.append_entry(
                request_id=request_id,
                app=first.get("app", args.app),
                resource_type=first.get("resource_type", "unknown"),
                requested_by=first.get("requested_by", ""),
                state_to=new_state,
                actor=args.signer,
                actor_role=getattr(args, "actor_role", "approver"),
                action="transition",
                notes=getattr(args, "notes", None),
            )
        except ValueError as e:
            sys.stderr.write(f"❌ Transición rechazada: {e}\n")
            return 1

        print(f"✓ Audit entry registrada · {entry.entry_id} · {entry.state_from} → {entry.state_to}")
        return 0

    # ---- Modo lectura ----
    return _print_audit_table(trail, args.app, args)


def _print_audit_table(trail, app: str, args: argparse.Namespace) -> int:
    """Tabla ASCII de status por request del aplicativo."""
    from aios.governance.audit_trail import AuditTrail

    request_ids = trail.list_request_ids(app=app)
    if not request_ids:
        print(f"  No hay solicitudes registradas para '{app}'.")
        print(f"  Ejecuta `aios governance request --type bd-access --app {app}` para empezar.")
        return 0

    # Verify chain integrity
    is_valid, errors = trail.verify_chain()

    print("=" * 84)
    print(f"  AIOS Governance Audit Trail · app={app}")
    print(f"  Audit file: {trail._path}")
    chain_marker = "✓ ÍNTEGRA" if is_valid else f"✗ TAMPERED · {len(errors)} errors"
    print(f"  Chain SHA: {chain_marker}")
    print("=" * 84)
    print()
    print(f"  {'REQUEST ID':<32}  {'TYPE':<22}  {'STATE':<14}  {'AGE'}")
    print(f"  {'-'*32}  {'-'*22}  {'-'*14}  {'-'*5}")

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    for rid in request_ids:
        entries = trail.list_entries(request_id=rid)
        last = entries[-1]
        rtype = last.get("resource_type", "?")
        state = last.get("state_to", "?")
        ts_str = last.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            age_days = (now - ts).days
            age_str = f"{age_days}d" if age_days > 0 else "<1d"
        except (ValueError, TypeError):
            age_str = "?"

        print(f"  {rid:<32}  {rtype:<22}  {state:<14}  {age_str}")

    print()

    # Slippage report
    slippages = trail.detect_slippage(app=app)
    if slippages:
        print("⚠ SLIPPAGE DETECTADO:")
        for s in slippages:
            print(f"  [{s['severity'].upper()}] {s['request_id']} · {s['days_in_current_state']}d · "
                  f"escalar a: {s['suggested_escalation']}")
        print()

    if not is_valid:
        print("✗ Chain corrupta · errores:")
        for err in errors[:5]:
            print(f"    - {err}")
        return 3

    return 0


# ---------------------------------------------------------------------------
# Subcommand 4 · governance escalate
# ---------------------------------------------------------------------------

def cmd_escalate(args: argparse.Namespace) -> int:
    """`aios governance escalate --app sicofav [--to elias | --auto]`

    Genera correo de escalación cuando una firma se atora >5 días:
      - Detección automática de slippage (vs thresholds en approvals.yaml)
      - Genera correo con bloqueadores listados + suggestions
      - Templates Markdown + PDF · adaptable destinatario
      - Cron-friendly mode (--auto · output JSON para scheduled trigger)

    Returns:
        0 OK · 1 si nada que escalar · 2 si destinatario inválido · 3 error
    """
    import json as _json
    from ..governance.escalation_engine import EscalationEngine
    from ..governance.loader import load_rules

    try:
        rules = load_rules()
    except (FileNotFoundError, Exception) as e:
        print(f"✗ Error cargando reglas governance: {e}", file=sys.stderr)
        return 3

    engine = EscalationEngine(rules)

    audit_root = Path(getattr(args, "audit_root", ".")).resolve()
    output_dir = Path(args.output).resolve()
    app_filter = None if args.app == "all" else args.app
    manual_to = None if args.to == "auto" else args.to
    days_override = args.days_threshold if args.days_threshold else None
    output_format = getattr(args, "format", "both")
    auto_mode = getattr(args, "auto", False)
    json_only = getattr(args, "json", False) or auto_mode

    try:
        artifacts = engine.generate(
            audit_root=audit_root,
            output_dir=output_dir,
            app=app_filter,
            manual_to=manual_to,
            days_threshold=days_override,
            write_pdf=(output_format in ("pdf", "both")),
            record_audit=True,
        )
    except ValueError as e:
        if json_only:
            print(_json.dumps({"status": "error", "error": str(e)}, indent=2))
        else:
            print(f"✗ {e}", file=sys.stderr)
        return 2
    except Exception as e:
        if json_only:
            print(_json.dumps(
                {"status": "error", "error_type": type(e).__name__, "error": str(e)},
                indent=2,
            ))
        else:
            print(f"✗ Error inesperado: {type(e).__name__}: {e}", file=sys.stderr)
        return 3

    if artifacts is None:
        if json_only:
            print(_json.dumps({
                "status": "no_slippage",
                "app": app_filter or "all",
                "thresholds": rules.approvals.get("slippage_thresholds", {}),
            }, indent=2))
        else:
            print(
                "✓ Sin solicitudes con slippage detectadas · "
                f"app={'all' if app_filter is None else app_filter} · "
                f"audit-root={audit_root}"
            )
        return 1

    if json_only:
        payload = {
            "status": "escalated",
            "severity": artifacts.severity,
            "slippage_count": artifacts.slippage_count,
            "request_id": artifacts.request_id,
            "escalation_to": artifacts.escalation_to,
            "markdown_path": str(artifacts.markdown_path) if artifacts.markdown_path else None,
            "pdf_path": str(artifacts.pdf_path) if artifacts.pdf_path else None,
            "audit_entry_recorded": artifacts.audit_entry_recorded,
            "slippages": [
                {k: v for k, v in s.items() if k != "last_entry_timestamp"}
                | {"last_entry_timestamp": s.get("last_entry_timestamp")}
                for s in artifacts.slippages
            ],
        }
        print(_json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    # Output humano
    icon = {"warn": "⚠", "escalate": "▲", "emergency": "■"}.get(artifacts.severity, "•")
    print(f"{icon} Escalación generada · severity={artifacts.severity} · "
          f"{artifacts.slippage_count} solicitudes en slippage")
    print(f"  → Destinatario: {artifacts.escalation_to['name']} · {artifacts.escalation_to['email']}")
    print(f"  → Request ID:    {artifacts.request_id}")
    print(f"  → Markdown:      {artifacts.markdown_path}")
    if artifacts.pdf_path:
        print(f"  → PDF:           {artifacts.pdf_path}")
    print(f"  → Audit entry:   {'✓ recorded' if artifacts.audit_entry_recorded else '✗ skipped'}")
    print()
    print("Solicitudes incluidas:")
    for s in artifacts.slippages:
        print(f"  · [{s['severity']:9s}] {s['request_id']} · {s['app']} · "
              f"{s['resource_type']} · {s['days_in_current_state']}d en '{s['state']}'")
    print()
    print(f"Próximo paso: enviar correo manualmente desde {artifacts.markdown_path}")
    print("o vía SMTP corporate (TODO post-v3.8.0).")
    return 0


# ---------------------------------------------------------------------------
# Subcommand 5 · tier classify (related but standalone)
# ---------------------------------------------------------------------------

def cmd_tier_classify(args: argparse.Namespace) -> int:
    """`aios tier classify --app sicofav [--explain]`

    Clasifica un aplicativo aplicando los 9 criterios oficiales AMX (tiers.yaml).

    Criterios evaluados:
      1. Impacto ingresos (alto/medio/bajo/muy bajo)
      2. Impacto servicio
      3. Impacto operación
      4. PII / PCI (Sí/No · KEY: T3 sólo si NO)
      5. Vigencia (permanente vs decomiso 18m)
      6. HA / Continuidad
      7. Disponibilidad target
      8. RTO / RPO
      9. Estrategia migración

    Detecta mismatch (caso SRG: declared T3 pero PII Sí → debería ser T2).

    Returns:
        0 si TIER coincide · 1 si mismatch detected · 2 si app no existe
    """
    import json as _json
    from ..governance.tier_classifier import TierClassifier

    classifier = TierClassifier()

    if args.app == "all":
        apps = classifier.list_apps()
    else:
        apps = [args.app]

    if args.format == "json":
        results_payload = []
        for app in apps:
            r = classifier.classify(app)
            results_payload.append({
                "app": r.app,
                "name": r.metadata.get("name"),
                "declared_tier": r.declared_tier.value if r.declared_tier else None,
                "computed_tier": r.computed_tier.value,
                "confidence": round(r.confidence, 2),
                "matches": r.matches,
                "mismatches": [
                    {
                        "rule_id": m.rule_id,
                        "severity": m.severity,
                        "reason": m.reason,
                        "suggested_tier": m.suggested_tier.value,
                    }
                    for m in r.mismatches
                ],
                "criteria": {
                    "impact_revenue": r.criteria_evaluated.impact_revenue,
                    "impact_service": r.criteria_evaluated.impact_service,
                    "impact_operation": r.criteria_evaluated.impact_operation,
                    "pci_pii": r.criteria_evaluated.pci_pii,
                    "vigencia_permanent": r.criteria_evaluated.vigencia_permanent,
                    "continuity_ha": r.criteria_evaluated.continuity_ha,
                    "rto_minutes": r.criteria_evaluated.rto_minutes,
                    "rpo_minutes": r.criteria_evaluated.rpo_minutes,
                    "estrategia_migracion": r.criteria_evaluated.estrategia_migracion,
                } if r.criteria_evaluated else None,
            })
        print(_json.dumps(results_payload, indent=2, ensure_ascii=False))
        any_mismatch = any(not r["matches"] for r in results_payload)
        return 1 if any_mismatch else 0

    # Output texto
    exit_code = 0
    for app in apps:
        r = classifier.classify(app)
        if r.declared_tier is None and not r.matches and not r.mismatches:
            print(f"✗ App '{app}' no encontrado en tiers.yaml.assignments")
            exit_code = max(exit_code, 2)
            continue

        icon = "✓" if r.matches else "▲"
        print("=" * 84)
        print(f"  {icon} {r.metadata.get('name', app)} · "
              f"declared={r.declared_tier.value if r.declared_tier else '?'} · "
              f"computed={r.computed_tier.value} · "
              f"confidence={r.confidence:.0%}")
        print("=" * 84)

        if args.explain and r.explanation:
            for line in r.explanation:
                print(f"  {line}")
        elif r.mismatches:
            print("  Mismatches:")
            for m in r.mismatches:
                print(f"    · [{m.severity}] {m.rule_id}: {m.reason}")
                print(f"          suggested: {m.suggested_tier.value}")
        else:
            print(f"  ✓ TIER coherente con los 9 criterios oficiales · "
                  f"status={r.metadata.get('tier_status')}")

        print()

        if not r.matches:
            exit_code = max(exit_code, 1)

    return exit_code


# ---------------------------------------------------------------------------
# CLI argparse setup · integration with aios main CLI
# ---------------------------------------------------------------------------

def add_governance_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Registra el subcomando 'governance' en el CLI principal de aios.

    Se invoca desde aios/cli/main.py durante setup."""

    p = subparsers.add_parser(
        "governance",
        help="AMX Governance Pack · check · request · audit · escalate (v3.8.0)",
    )
    sub = p.add_subparsers(dest="governance_action", required=True)

    # check
    p_check = sub.add_parser("check", help="Valida reglas AMX para un aplicativo")
    p_check.add_argument("--app", required=True, help="App key (sicofav · robot · etc.)")
    p_check.add_argument("--root", default=".", help="Path raíz del aplicativo")
    p_check.add_argument("--strict", action="store_true", help="Falla en WARN · no solo FAIL")
    p_check.add_argument("--format", choices=["text", "json"], default="text")
    p_check.set_defaults(func=cmd_check)

    # request
    p_req = sub.add_parser("request", help="Genera PDF formal de solicitud")
    p_req.add_argument(
        "--type",
        required=True,
        choices=[t.value for t in ResourceType],
        help="Tipo de recurso solicitado",
    )
    p_req.add_argument("--app", required=True, help="App key")
    p_req.add_argument("--output", default="./governance-requests/", help="Directorio output")
    p_req.add_argument("--format", choices=["pdf", "md", "both"], default="both")
    p_req.add_argument("--requester", help="Email del solicitante · default: admin del equipo eTribe")
    p_req.add_argument("--audit-root", default=".", help="Root para .aios/governance/audit-trail.jsonl")
    p_req.set_defaults(func=cmd_request)

    # audit
    p_aud = sub.add_parser("audit", help="Audit trail 5 firmas en cadena")
    p_aud.add_argument("--app", required=True)
    p_aud.add_argument("--audit-root", default=".",
                       help="Root para .aios/governance/audit-trail.jsonl")
    p_aud.add_argument("--update", action="store_true", help="Actualiza estado de firma")
    p_aud.add_argument("--signer", help="Nombre/email del firmante (con --update)")
    p_aud.add_argument(
        "--status",
        choices=[
            "draft", "requested", "in-review", "partially-approved",
            "approved", "rejected", "provisioned", "renewed", "expired",
            "cancelled", "revoked",
        ],
        help="Nuevo estado de la solicitud",
    )
    p_aud.add_argument(
        "--request-id",
        help="ID de la solicitud · si se omite con --update usa la más reciente del app",
    )
    p_aud.add_argument("--actor-role",
                       choices=["pm", "dba", "cyber", "rc-osorio", "borde", "approver", "system"],
                       default="approver")
    p_aud.add_argument("--notes", help="Notas para esta entry de audit")
    p_aud.set_defaults(func=cmd_audit)

    # escalate
    p_esc = sub.add_parser("escalate", help="Genera correo escalación slippage")
    p_esc.add_argument("--app", required=True,
                       help="App key (sicofav · robot · ... · 'all' para todos)")
    p_esc.add_argument(
        "--to",
        choices=["luis", "elias", "sponsor", "victor", "miguel-rachid", "auto"],
        default="auto",
        help="Destinatario · auto = severity routing (warn→Luis · escalate→Elías · emergency→sponsor)",
    )
    p_esc.add_argument("--days-threshold", type=int, default=0,
                       help="Override warn_after_days · 0 = usa approvals.yaml")
    p_esc.add_argument("--output", default="./governance-escalations/")
    p_esc.add_argument("--audit-root", default=".",
                       help="Root para .aios/governance/audit-trail.jsonl")
    p_esc.add_argument("--format", choices=["pdf", "md", "both"], default="both")
    p_esc.add_argument("--auto", action="store_true",
                       help="Cron-friendly · output JSON · sin prompts (alias --json)")
    p_esc.add_argument("--json", action="store_true",
                       help="Output JSON estable · útil para scheduled triggers")
    p_esc.set_defaults(func=cmd_escalate)


def add_tier_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Registra el subcomando 'tier' (relacionado · standalone)."""

    p = subparsers.add_parser("tier", help="TIER classification por aplicativo")
    sub = p.add_subparsers(dest="tier_action", required=True)

    p_class = sub.add_parser("classify", help="Clasifica app por criterios oficiales")
    p_class.add_argument("--app", required=True)
    p_class.add_argument("--explain", action="store_true", help="Muestra los 9 criterios evaluados")
    p_class.add_argument("--format", choices=["text", "json"], default="text")
    p_class.set_defaults(func=cmd_tier_classify)


# ---------------------------------------------------------------------------
# Helpers públicos · API programática
# ---------------------------------------------------------------------------

def load_governance_rules() -> dict[str, Any]:
    """Carga los 4 YAMLs de aios/governance/rules/ y retorna dict consolidado.

    Returns:
        {
            "tiers": dict,
            "approvals": dict,
            "naming": dict,
            "stakeholders": dict,
        }
    """
    # F2 Día 3 · implementación · usar yaml.safe_load
    raise NotImplementedError("F2 Día 3 · 01-may")


def get_app_metadata(app: str) -> dict[str, Any]:
    """Retorna metadata del aplicativo desde tiers.yaml.assignments[app]."""
    # F2 Día 3 · implementación
    raise NotImplementedError("F2 Día 3 · 01-may")


def list_supported_apps() -> list[str]:
    """Retorna las 8 keys de aplicativos soportados."""
    return ["sicofav", "arc", "bsp", "cfdi", "srg", "asr", "robot", "noshow"]


# ---------------------------------------------------------------------------
# Entry point · for `python -m aios.cli.governance` standalone
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="aios-governance")
    sub = parser.add_subparsers(dest="command", required=True)
    add_governance_subcommand(sub)
    add_tier_subcommand(sub)
    args = parser.parse_args()
    sys.exit(args.func(args))
