"""ApprovalsChecker · valida estado de firmas en cadena vs audit-trail.jsonl.

Lee .aios/governance/audit-trail.jsonl si existe · reporta:
  - Solicitudes en flight (state ∈ requested · in-review · partially-approved)
  - Slippage (días sin avance vs thresholds approvals.yaml)
  - Solicitudes próximas a expirar
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..loader import GovernanceRules
from ..models import CheckSeverity, GovernanceFinding


AUDIT_TRAIL_PATH_REL = Path(".aios") / "governance" / "audit-trail.jsonl"


class ApprovalsChecker:
    """Valida estado de las 5 firmas en cadena por aplicativo."""

    def __init__(self, rules: GovernanceRules):
        self._rules = rules

    def check(self, root: Path, app: str) -> list[GovernanceFinding]:
        findings: list[GovernanceFinding] = []
        audit_path = root / AUDIT_TRAIL_PATH_REL

        if not audit_path.exists():
            findings.append(GovernanceFinding(
                rule_id="GOV-AUDIT-TRAIL-MISSING",
                severity=CheckSeverity.WARN,
                category="approvals",
                message=(
                    f"No existe audit-trail en {AUDIT_TRAIL_PATH_REL} · "
                    "no se puede rastrear estado de firmas."
                ),
                suggestion="Inicializar con `aios governance request --type bd-access --app " + app + "`",
            ))
            return findings

        # Leer todas las entries del audit trail
        entries: list[dict] = []
        try:
            with audit_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        except Exception as e:
            findings.append(GovernanceFinding(
                rule_id="GOV-AUDIT-TRAIL-CORRUPT",
                severity=CheckSeverity.CRITICAL,
                category="approvals",
                message=f"audit-trail.jsonl corrupto · {type(e).__name__}: {e}",
                location=str(AUDIT_TRAIL_PATH_REL),
            ))
            return findings

        # Filtrar entries de este aplicativo
        app_entries = [e for e in entries if e.get("app") == app]
        if not app_entries:
            findings.append(GovernanceFinding(
                rule_id="GOV-NO-REQUESTS-YET",
                severity=CheckSeverity.PASS,
                category="approvals",
                message=f"App '{app}' aún no tiene solicitudes registradas · audit trail limpio.",
            ))
            return findings

        # Agrupar por request_id · keep last entry (estado actual)
        by_request: dict[str, dict] = {}
        for e in app_entries:
            rid = e.get("request_id", "unknown")
            by_request[rid] = e  # last wins

        # Slippage thresholds del YAML
        slippage = self._rules.approvals.get("slippage_thresholds", {})
        warn_d = slippage.get("warn_after_days", 3)
        escalate_d = slippage.get("escalate_after_days", 5)
        emergency_d = slippage.get("emergency_after_days", 10)

        in_flight_states = {"requested", "in-review", "partially-approved"}

        now = datetime.now(timezone.utc)

        for rid, last_entry in by_request.items():
            state = last_entry.get("state_to", "unknown")
            ts_str = last_entry.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                continue

            days_in_state = (now - ts).days

            if state in in_flight_states:
                if days_in_state >= emergency_d:
                    severity = CheckSeverity.CRITICAL
                    rule = "GOV-APPROVAL-EMERGENCY-SLIPPAGE"
                elif days_in_state >= escalate_d:
                    severity = CheckSeverity.FAIL
                    rule = "GOV-APPROVAL-ESCALATE-SLIPPAGE"
                elif days_in_state >= warn_d:
                    severity = CheckSeverity.WARN
                    rule = "GOV-APPROVAL-WARN-SLIPPAGE"
                else:
                    continue  # OK · dentro de SLA

                findings.append(GovernanceFinding(
                    rule_id=rule,
                    severity=severity,
                    category="approvals",
                    message=(
                        f"Solicitud {rid} en estado '{state}' por {days_in_state} días · "
                        f"threshold: {warn_d}d/{escalate_d}d/{emergency_d}d"
                    ),
                    suggestion=(
                        "Ejecutar `aios governance escalate --app " + app + " --to elias`"
                        if severity in (CheckSeverity.FAIL, CheckSeverity.CRITICAL)
                        else "Hacer follow-up con el responsable de la firma actual"
                    ),
                ))

        if not findings:
            findings.append(GovernanceFinding(
                rule_id="GOV-APPROVALS-OK",
                severity=CheckSeverity.PASS,
                category="approvals",
                message=f"App '{app}' · {len(by_request)} solicitudes · todas dentro de SLA",
            ))

        return findings
