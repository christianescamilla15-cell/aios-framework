"""AIOS Governance · AuditTrail · persistencia jsonl tamper-evident para 5 firmas en cadena.

Diseño:
  - Append-only JSONL (.aios/governance/audit-trail.jsonl)
  - SHA256 chain entre entries (cada entry incluye SHA256 del anterior)
  - State machine de 11 estados (approvals.yaml.audit_states)
  - Validación de transiciones · NO se puede ir de approved → in-review

Status: SKELETON · diseño v3.8.0 F1 Día 2 · 28-abr-2026
Implementación real: F2 Día 5 · 05-may-2026
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# State machine · 11 estados (matchea approvals.yaml.audit_states)
# ---------------------------------------------------------------------------

class AuditState(str, Enum):
    DRAFT = "draft"
    REQUESTED = "requested"
    IN_REVIEW = "in-review"
    PARTIALLY_APPROVED = "partially-approved"
    APPROVED = "approved"
    PROVISIONED = "provisioned"
    RENEWED = "renewed"
    EXPIRED = "expired"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    REVOKED = "revoked"


# Transiciones válidas · matchea approvals.yaml.audit_states.next_states
VALID_TRANSITIONS: dict[AuditState, set[AuditState]] = {
    AuditState.DRAFT: {AuditState.REQUESTED, AuditState.CANCELLED},
    AuditState.REQUESTED: {AuditState.IN_REVIEW, AuditState.REJECTED, AuditState.CANCELLED},
    AuditState.IN_REVIEW: {AuditState.PARTIALLY_APPROVED, AuditState.APPROVED, AuditState.REJECTED, AuditState.EXPIRED},
    AuditState.PARTIALLY_APPROVED: {AuditState.APPROVED, AuditState.EXPIRED, AuditState.REJECTED},
    AuditState.APPROVED: {AuditState.PROVISIONED, AuditState.EXPIRED},
    AuditState.PROVISIONED: {AuditState.RENEWED, AuditState.EXPIRED, AuditState.REVOKED},
    AuditState.RENEWED: {AuditState.PROVISIONED, AuditState.EXPIRED, AuditState.REVOKED},
    AuditState.EXPIRED: {AuditState.RENEWED},
    # Final states · sin transiciones outgoing
    AuditState.REJECTED: set(),
    AuditState.CANCELLED: set(),
    AuditState.REVOKED: set(),
}


# ---------------------------------------------------------------------------
# Audit entry · una línea del jsonl
# ---------------------------------------------------------------------------

@dataclass
class AuditEntry:
    """Una entrada inmutable del audit trail."""

    # Identificación
    entry_id: str           # ULID o UUID v7 · ordenable por tiempo
    request_id: str         # ID de la solicitud (ej. GOV-SICOFAV-BD-20260428-001)
    timestamp: str          # ISO 8601 UTC

    # Contexto
    app: str                # sicofav · robot · etc.
    resource_type: str      # bd-access · aws-account · etc. (matchea approvals.yaml)
    requested_by: str       # Email del solicitante

    # Cambio de estado
    state_from: str | None  # AuditState · None si es la primera entry
    state_to: str           # AuditState

    # Acción
    action: str             # "create" · "transition" · "update" · "expire"
    actor: str              # Email del actor que realiza la acción
    actor_role: str         # PM · DBA · CYBER · RC · Borde · system

    # Tamper-evident
    prev_hash: str | None   # SHA256 de la entry anterior · None si first
    entry_hash: str | None = None  # SHA256 de esta entry (calculado al persistir)

    # Metadata opcional
    metadata: dict[str, Any] = field(default_factory=dict)
    notes: str | None = None

    def compute_hash(self) -> str:
        """Calcula SHA256 de la entry (excluyendo entry_hash propio · evita recursión).

        IMPORTANTE: usa ensure_ascii=False para consistencia con _recompute_entry_hash
        en AuditTrail · si esto cambia, la chain entera deja de validar.
        """
        d = asdict(self)
        d.pop("entry_hash", None)
        canonical = json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Audit trail · persistence layer
# ---------------------------------------------------------------------------

class AuditTrail:
    """Audit trail append-only con SHA chain.

    Persistencia: .aios/governance/audit-trail.jsonl

    Usage:
        trail = AuditTrail(Path(".aios/governance/audit-trail.jsonl"))
        trail.append_entry(
            request_id="GOV-SICOFAV-BD-001",
            app="sicofav",
            resource_type="bd-access",
            requested_by="chernandeze@aeromexico.com",
            state_to=AuditState.REQUESTED,
            actor="chernandeze@aeromexico.com",
            actor_role="requester",
        )

        # Validación de chain
        is_valid = trail.verify_chain()  # True si SHA chain íntegra

        # Lectura
        entries = trail.list_entries(request_id="GOV-SICOFAV-BD-001")
    """

    def __init__(self, path: Path):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # API pública · IMPLEMENTADA F2 Día 5
    # -----------------------------------------------------------------------

    def _read_all(self) -> list[dict[str, Any]]:
        """Lee todas las entries del jsonl (raw dicts)."""
        if not self._path.exists():
            return []
        entries: list[dict[str, Any]] = []
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # skip línea malformed · validate_chain reporta
        return entries

    def append_entry(
        self,
        request_id: str,
        app: str,
        resource_type: str,
        requested_by: str,
        state_to: AuditState,
        actor: str,
        actor_role: str,
        action: str = "transition",
        notes: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Agrega una nueva entry · calcula SHA chain · valida transición.

        Raises:
            ValueError si transición de estado no es válida para la solicitud.
            IOError si no puede escribir el jsonl.
        """
        existing = self._read_all()
        prev_hash = existing[-1].get("entry_hash") if existing else None

        # State transition validation
        request_entries = [e for e in existing if e.get("request_id") == request_id]
        state_from: AuditState | None = None
        if request_entries:
            last_state_str = request_entries[-1].get("state_to")
            try:
                state_from = AuditState(last_state_str) if last_state_str else None
            except ValueError:
                state_from = None  # estado desconocido · permitir override

        if not self.is_valid_transition(state_from, state_to):
            raise ValueError(
                f"Transición inválida: {state_from} → {state_to} "
                f"(request_id={request_id}). "
                f"Transiciones válidas desde {state_from}: "
                f"{[s.value for s in VALID_TRANSITIONS.get(state_from, set())] if state_from else ['draft', 'requested']}"
            )

        ts = datetime.now(timezone.utc).isoformat()
        # entry_id determinístico desde request_id+timestamp+state
        entry_id = hashlib.sha256(
            f"{request_id}-{ts}-{state_to.value}".encode("utf-8")
        ).hexdigest()[:16]

        entry = AuditEntry(
            entry_id=entry_id,
            request_id=request_id,
            timestamp=ts,
            app=app,
            resource_type=resource_type,
            requested_by=requested_by,
            state_from=(state_from.value if state_from else None),
            state_to=state_to.value,
            action=action,
            actor=actor,
            actor_role=actor_role,
            prev_hash=prev_hash,
            metadata=metadata or {},
            notes=notes,
        )
        entry.entry_hash = entry.compute_hash()

        # Append a jsonl
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")

        return entry

    def list_entries(
        self,
        request_id: str | None = None,
        app: str | None = None,
        state: AuditState | None = None,
    ) -> list[dict[str, Any]]:
        """Lista entries con filtros opcionales."""
        entries = self._read_all()
        if request_id:
            entries = [e for e in entries if e.get("request_id") == request_id]
        if app:
            entries = [e for e in entries if e.get("app") == app]
        if state:
            entries = [e for e in entries if e.get("state_to") == state.value]
        return entries

    def list_request_ids(self, app: str | None = None) -> list[str]:
        """Retorna lista única de request_ids."""
        entries = self._read_all()
        if app:
            entries = [e for e in entries if e.get("app") == app]
        seen: list[str] = []
        for e in entries:
            rid = e.get("request_id")
            if rid and rid not in seen:
                seen.append(rid)
        return seen

    def get_current_state(self, request_id: str) -> AuditState | None:
        """Retorna el estado actual de una solicitud (última entry)."""
        entries = self.list_entries(request_id=request_id)
        if not entries:
            return None
        last = entries[-1]
        try:
            return AuditState(last.get("state_to"))
        except ValueError:
            return None

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Valida que el SHA chain está íntegro (NO tampering).

        Returns:
            (True, []) si chain íntegra.
            (False, [errors...]) si hay tampering · errors describe entries inconsistentes.
        """
        entries = self._read_all()
        if not entries:
            return True, []

        errors: list[str] = []
        prev_hash: str | None = None

        for i, e in enumerate(entries):
            stored_prev = e.get("prev_hash")
            if stored_prev != prev_hash:
                errors.append(
                    f"Entry {i} ({e.get('entry_id', 'unknown')}): "
                    f"prev_hash={stored_prev!r} pero esperado={prev_hash!r}"
                )

            # Recompute entry_hash and compare
            stored_entry_hash = e.get("entry_hash")
            recomputed = self._recompute_entry_hash(e)
            if stored_entry_hash and stored_entry_hash != recomputed:
                errors.append(
                    f"Entry {i} ({e.get('entry_id', 'unknown')}): "
                    f"entry_hash inconsistente · stored={stored_entry_hash[:12]}... "
                    f"computed={recomputed[:12]}..."
                )

            prev_hash = stored_entry_hash

        return (len(errors) == 0), errors

    @staticmethod
    def _recompute_entry_hash(entry_dict: dict[str, Any]) -> str:
        """Recomputa el SHA256 de una entry desde su dict (para verify_chain)."""
        d = {k: v for k, v in entry_dict.items() if k != "entry_hash"}
        canonical = json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def detect_slippage(
        self,
        warn_after_days: int = 3,
        escalate_after_days: int = 5,
        emergency_after_days: int = 10,
        app: str | None = None,
    ) -> list[dict[str, Any]]:
        """Detecta solicitudes con slippage (firma sin avance > X días).

        Returns lista de dicts con:
            - request_id · app · resource_type
            - state · days_in_current_state
            - severity ('warn' | 'escalate' | 'emergency')
            - suggested_escalation
        """
        in_flight = {"requested", "in-review", "partially-approved"}
        now = datetime.now(timezone.utc)

        # Última entry por request_id
        last_by_req: dict[str, dict[str, Any]] = {}
        for e in self._read_all():
            if app and e.get("app") != app:
                continue
            rid = e.get("request_id")
            if rid:
                last_by_req[rid] = e

        slippages: list[dict[str, Any]] = []
        for rid, e in last_by_req.items():
            state = e.get("state_to")
            if state not in in_flight:
                continue
            try:
                ts = datetime.fromisoformat(e.get("timestamp", "").replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue
            days = (now - ts).days

            if days >= emergency_after_days:
                severity = "emergency"
            elif days >= escalate_after_days:
                severity = "escalate"
            elif days >= warn_after_days:
                severity = "warn"
            else:
                continue

            slippages.append({
                "request_id": rid,
                "app": e.get("app"),
                "resource_type": e.get("resource_type"),
                "state": state,
                "days_in_current_state": days,
                "severity": severity,
                "suggested_escalation": (
                    "Elías Tapia (sponsor único)" if severity == "emergency"
                    else "Luis Ertuche (PM intermediación)"
                ),
                "last_entry_timestamp": e.get("timestamp"),
            })

        return slippages

    # -----------------------------------------------------------------------
    # Validación de transiciones
    # -----------------------------------------------------------------------

    @staticmethod
    def is_valid_transition(state_from: AuditState | None, state_to: AuditState) -> bool:
        """Valida si una transición de estado es válida.

        Si state_from is None · solo se permite REQUESTED o DRAFT (initial states).
        """
        if state_from is None:
            return state_to in {AuditState.DRAFT, AuditState.REQUESTED}
        return state_to in VALID_TRANSITIONS.get(state_from, set())


# ---------------------------------------------------------------------------
# Helpers · funciones de conveniencia
# ---------------------------------------------------------------------------

def default_audit_path(repo_root: Path | None = None) -> Path:
    """Retorna path estándar para audit-trail.jsonl en un repo aplicativo."""
    if repo_root is None:
        repo_root = Path.cwd()
    return repo_root / ".aios" / "governance" / "audit-trail.jsonl"


def generate_request_id(
    resource_type: str,
    app: str,
    timestamp: datetime | None = None,
    sequence: int = 1,
) -> str:
    """Genera request ID determinístico.

    Formato: GOV-{APP}-{TYPE}-{YYYYMMDD}-{NNN}
    Ejemplo: GOV-SICOFAV-BD-20260428-001
    """
    ts = timestamp or datetime.utcnow()
    type_short = {
        "bd-access": "BD",
        "aws-account-dedicated": "AWS",
        "aws-account-shared": "AWST2",
        "cmk-request": "CMK",
        "yubikey-request": "YBK",
        "iam-role": "IAM",
        "vpc-cidr": "VPC",
        "adr-signature": "ADR",
        "tier-reclassification": "TIER",
        "custodia-external": "CUST",
        "scope-change": "SCOPE",
        "dl-inclusion": "DL",
    }.get(resource_type, "GEN")

    return f"GOV-{app.upper()}-{type_short}-{ts.strftime('%Y%m%d')}-{sequence:03d}"
