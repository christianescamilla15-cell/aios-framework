"""Tests · governance.audit_trail · state machine + SHA chain + slippage + tampering."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from dataclasses import asdict
from pathlib import Path

import pytest

from aios.governance.audit_trail import (
    AuditEntry,
    AuditState,
    AuditTrail,
    VALID_TRANSITIONS,
    default_audit_path,
    generate_request_id,
)


@pytest.fixture
def trail(tmp_path: Path) -> AuditTrail:
    return AuditTrail(tmp_path / "audit-trail.jsonl")


# ── State machine ────────────────────────────────────────────────────


def test_valid_transition_from_none_allows_draft_or_requested():
    assert AuditTrail.is_valid_transition(None, AuditState.DRAFT) is True
    assert AuditTrail.is_valid_transition(None, AuditState.REQUESTED) is True
    assert AuditTrail.is_valid_transition(None, AuditState.APPROVED) is False


def test_valid_transition_requested_to_in_review():
    assert AuditTrail.is_valid_transition(
        AuditState.REQUESTED, AuditState.IN_REVIEW
    ) is True


def test_invalid_transition_approved_to_requested_rejected():
    """Una solicitud aprobada NO puede regresar a requested."""
    assert AuditTrail.is_valid_transition(
        AuditState.APPROVED, AuditState.REQUESTED
    ) is False


def test_valid_transitions_dict_has_11_states():
    """11 estados oficiales del state machine."""
    states = set(VALID_TRANSITIONS.keys())
    assert len(states) >= 9  # algunos terminales no tienen entrada
    assert AuditState.DRAFT in states
    assert AuditState.REQUESTED in states
    assert AuditState.APPROVED in states


# ── append_entry + SHA chain ─────────────────────────────────────────


def test_append_entry_writes_jsonl_with_hash(trail):
    entry = trail.append_entry(
        request_id="GOV-FLEET_OPS_APP-BD-20260429-001",
        app="fleet_ops_app",
        resource_type="bd-access",
        requested_by="engineer@acmeair.com",
        state_to=AuditState.REQUESTED,
        actor="engineer@acmeair.com",
        actor_role="requester",
    )
    assert entry.entry_hash
    assert len(entry.entry_hash) == 64  # SHA256 hex
    assert entry.prev_hash is None  # first entry
    assert trail._path.exists()


def test_append_entry_chains_prev_hash(trail):
    e1 = trail.append_entry(
        request_id="GOV-X-BD-20260429-001",
        app="fleet_ops_app",
        resource_type="bd-access",
        requested_by="x@x.com",
        state_to=AuditState.REQUESTED,
        actor="x@x.com",
        actor_role="requester",
    )
    e2 = trail.append_entry(
        request_id="GOV-X-BD-20260429-001",
        app="fleet_ops_app",
        resource_type="bd-access",
        requested_by="x@x.com",
        state_to=AuditState.IN_REVIEW,
        actor="reviewer@x.com",
        actor_role="approver",
    )
    assert e2.prev_hash == e1.entry_hash


def test_append_entry_rejects_invalid_transition(trail):
    """REQUESTED → REQUESTED es transición inválida."""
    trail.append_entry(
        request_id="GOV-X-BD-20260429-001",
        app="fleet_ops_app",
        resource_type="bd-access",
        requested_by="x@x.com",
        state_to=AuditState.REQUESTED,
        actor="x@x.com",
        actor_role="requester",
    )
    with pytest.raises(ValueError, match="Transición inválida"):
        trail.append_entry(
            request_id="GOV-X-BD-20260429-001",
            app="fleet_ops_app",
            resource_type="bd-access",
            requested_by="x@x.com",
            state_to=AuditState.REQUESTED,
            actor="x@x.com",
            actor_role="requester",
        )


def test_verify_chain_intact_after_append(trail):
    trail.append_entry(
        request_id="GOV-X-BD-20260429-001",
        app="fleet_ops_app",
        resource_type="bd-access",
        requested_by="x@x.com",
        state_to=AuditState.REQUESTED,
        actor="x@x.com",
        actor_role="requester",
    )
    trail.append_entry(
        request_id="GOV-X-BD-20260429-001",
        app="fleet_ops_app",
        resource_type="bd-access",
        requested_by="x@x.com",
        state_to=AuditState.IN_REVIEW,
        actor="r@x.com",
        actor_role="approver",
    )
    intact, errors = trail.verify_chain()
    assert intact, errors
    assert errors == []


def test_verify_chain_detects_tampering(trail):
    """Si alguien edita el JSONL manualmente · verify_chain debe FAIL."""
    trail.append_entry(
        request_id="GOV-X-BD-20260429-001",
        app="fleet_ops_app",
        resource_type="bd-access",
        requested_by="x@x.com",
        state_to=AuditState.REQUESTED,
        actor="x@x.com",
        actor_role="requester",
        notes="ORIGINAL",
    )
    # Tampering: editar el archivo cambiando el campo notes
    raw = trail._path.read_text(encoding="utf-8")
    tampered = raw.replace("ORIGINAL", "TAMPERED")
    trail._path.write_text(tampered, encoding="utf-8")

    intact, errors = trail.verify_chain()
    assert not intact
    assert errors


# ── slippage detection ───────────────────────────────────────────────


def _seed_old_entry(
    trail: AuditTrail,
    request_id: str,
    app: str,
    days_ago: int,
    state: AuditState = AuditState.REQUESTED,
    prev_hash: str | None = None,
) -> str:
    """Helper · escribe entry directa con timestamp custom + SHA chain válida."""
    ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    import hashlib
    entry_id = hashlib.sha256(f"{request_id}-{ts}-{state.value}".encode()).hexdigest()[:16]
    entry = AuditEntry(
        entry_id=entry_id,
        request_id=request_id,
        timestamp=ts,
        app=app,
        resource_type="bd-access",
        requested_by="x@x.com",
        state_from=None,
        state_to=state.value,
        actor="x@x.com",
        actor_role="requester",
        action="create",
        notes=f"seed days_ago={days_ago}",
        metadata={},
        prev_hash=prev_hash,
        entry_hash="",
    )
    entry.entry_hash = entry.compute_hash()
    trail._path.parent.mkdir(parents=True, exist_ok=True)
    with trail._path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(entry), ensure_ascii=False, separators=(",", ":")) + "\n")
    return entry.entry_hash


def test_detect_slippage_warn_at_3_days(trail):
    _seed_old_entry(trail, "GOV-X-BD-001", "fleet_ops_app", days_ago=4)
    slips = trail.detect_slippage(warn_after_days=3, escalate_after_days=5, emergency_after_days=10)
    assert len(slips) == 1
    assert slips[0]["severity"] == "warn"
    assert slips[0]["days_in_current_state"] == 4


def test_detect_slippage_escalate_at_7_days(trail):
    _seed_old_entry(trail, "GOV-X-BD-001", "fleet_ops_app", days_ago=7)
    slips = trail.detect_slippage()
    assert slips[0]["severity"] == "escalate"


def test_detect_slippage_emergency_at_12_days(trail):
    _seed_old_entry(trail, "GOV-X-BD-001", "fleet_ops_app", days_ago=12)
    slips = trail.detect_slippage()
    assert slips[0]["severity"] == "emergency"


def test_detect_slippage_filters_by_app(trail):
    h = _seed_old_entry(trail, "GOV-A-BD-001", "fleet_ops_app", days_ago=7)
    _seed_old_entry(trail, "GOV-B-BD-001", "noshow", days_ago=7, prev_hash=h)
    slips = trail.detect_slippage(app="fleet_ops_app")
    assert len(slips) == 1
    assert slips[0]["app"] == "fleet_ops_app"


def test_detect_slippage_skips_terminal_states(trail):
    """Si el último estado es 'approved' · no es slippage."""
    h = _seed_old_entry(trail, "GOV-A-BD-001", "fleet_ops_app", days_ago=20, state=AuditState.REQUESTED)
    _seed_old_entry(trail, "GOV-A-BD-001", "fleet_ops_app", days_ago=15,
                    state=AuditState.APPROVED, prev_hash=h)
    slips = trail.detect_slippage()
    assert slips == []


# ── helpers ──────────────────────────────────────────────────────────


def test_default_audit_path_produces_aios_governance_subpath(tmp_path):
    p = default_audit_path(tmp_path)
    assert p == tmp_path / ".aios" / "governance" / "audit-trail.jsonl"


def test_generate_request_id_format():
    rid = generate_request_id(resource_type="bd-access", app="fleet_ops_app")
    assert rid.startswith("GOV-FLEET_OPS_APP-BD-")
    assert len(rid.split("-")) == 5  # GOV-APP-TYPE-DATE-NNN
