"""Tests · governance.escalation_engine · auto-routing severity + slippage."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib

import pytest

from aios.governance.audit_trail import AuditEntry, AuditState
from aios.governance.escalation_engine import EscalationEngine
from aios.governance.loader import load_rules, reset_cache


@pytest.fixture(autouse=True)
def _reset_cache():
    reset_cache()
    yield
    reset_cache()


@pytest.fixture
def engine():
    return EscalationEngine(load_rules())


def _seed_audit_with_old_entries(audit_root, slippages):
    """Helper · escribe audit-trail.jsonl con entries con timestamps específicos.

    slippages = [(request_id, app, resource_type, days_ago), ...]
    """
    audit_path = audit_root / ".aios" / "governance" / "audit-trail.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    prev_hash = None
    with audit_path.open("w", encoding="utf-8") as f:
        for rid, app, rtype, days_ago in slippages:
            ts = (now - timedelta(days=days_ago)).isoformat()
            entry_id = hashlib.sha256(f"{rid}-{ts}-requested".encode()).hexdigest()[:16]
            entry = AuditEntry(
                entry_id=entry_id,
                request_id=rid,
                timestamp=ts,
                app=app,
                resource_type=rtype,
                requested_by="x@x.com",
                state_from=None,
                state_to=AuditState.REQUESTED.value,
                actor="x@x.com",
                actor_role="requester",
                action="create",
                notes=f"seed days_ago={days_ago}",
                metadata={},
                prev_hash=prev_hash,
                entry_hash="",
            )
            entry.entry_hash = entry.compute_hash()
            f.write(json.dumps(asdict(entry), ensure_ascii=False, separators=(",", ":")) + "\n")
            prev_hash = entry.entry_hash


# ── detect ────────────────────────────────────────────────────────────


def test_detect_returns_empty_when_no_audit(tmp_path, engine):
    slips = engine.detect(audit_root=tmp_path)
    assert slips == []


def test_detect_returns_slippages_with_severity(tmp_path, engine):
    _seed_audit_with_old_entries(tmp_path, [
        ("GOV-FLEET_OPS_APP-BD-001", "fleet_ops_app", "bd-access", 4),
        ("GOV-FLEET_OPS_APP-CMK-001", "fleet_ops_app", "cmk-request", 7),
        ("GOV-FLEET_OPS_APP-AWS-001", "fleet_ops_app", "aws-account-shared", 12),
    ])
    slips = engine.detect(audit_root=tmp_path, app="fleet_ops_app")
    assert len(slips) == 3
    severities = {s["severity"] for s in slips}
    assert severities == {"warn", "escalate", "emergency"}


# ── auto-routing ──────────────────────────────────────────────────────


def test_emergency_routes_to_sponsor_business(tmp_path, engine):
    _seed_audit_with_old_entries(tmp_path, [
        ("GOV-FLEET_OPS_APP-AWS-001", "fleet_ops_app", "aws-account-shared", 12),
    ])
    artifacts = engine.generate(
        audit_root=tmp_path,
        output_dir=tmp_path / "esc",
        app="fleet_ops_app",
        write_pdf=False,
    )
    assert artifacts.severity == "emergency"
    assert "Víctor" in artifacts.escalation_to["name"] or "sponsor" in artifacts.escalation_to["role"].lower()


def test_escalate_routes_to_elias(tmp_path, engine):
    _seed_audit_with_old_entries(tmp_path, [
        ("GOV-FLEET_OPS_APP-BD-001", "fleet_ops_app", "bd-access", 7),
    ])
    artifacts = engine.generate(
        audit_root=tmp_path,
        output_dir=tmp_path / "esc",
        app="fleet_ops_app",
        write_pdf=False,
    )
    assert artifacts.severity == "escalate"
    assert artifacts.escalation_to["email"] == "etapia@acmeair.com"


def test_warn_routes_to_luis(tmp_path, engine):
    _seed_audit_with_old_entries(tmp_path, [
        ("GOV-FLEET_OPS_APP-BD-001", "fleet_ops_app", "bd-access", 4),
    ])
    artifacts = engine.generate(
        audit_root=tmp_path,
        output_dir=tmp_path / "esc",
        app="fleet_ops_app",
        write_pdf=False,
    )
    assert artifacts.severity == "warn"
    assert artifacts.escalation_to["email"] == "luisertuche@acmeair.com"


# ── manual override ──────────────────────────────────────────────────


def test_manual_to_overrides_severity_routing(tmp_path, engine):
    _seed_audit_with_old_entries(tmp_path, [
        ("GOV-FLEET_OPS_APP-AWS-001", "fleet_ops_app", "aws-account-shared", 12),
    ])
    # Severity emergency · pero manual override = luis
    artifacts = engine.generate(
        audit_root=tmp_path,
        output_dir=tmp_path / "esc",
        app="fleet_ops_app",
        manual_to="luis",
        write_pdf=False,
    )
    assert artifacts.severity == "emergency"  # severity NO cambia
    assert "Luis" in artifacts.escalation_to["name"]


def test_manual_to_invalid_raises(tmp_path, engine):
    _seed_audit_with_old_entries(tmp_path, [
        ("GOV-FLEET_OPS_APP-BD-001", "fleet_ops_app", "bd-access", 4),
    ])
    with pytest.raises(ValueError, match="--to 'invalid_target'"):
        engine.generate(
            audit_root=tmp_path,
            output_dir=tmp_path / "esc",
            app="fleet_ops_app",
            manual_to="invalid_target",
            write_pdf=False,
        )


# ── markdown output ──────────────────────────────────────────────────


def test_markdown_output_contains_severity_and_app(tmp_path, engine):
    _seed_audit_with_old_entries(tmp_path, [
        ("GOV-FLEET_OPS_APP-BD-001", "fleet_ops_app", "bd-access", 4),
    ])
    artifacts = engine.generate(
        audit_root=tmp_path,
        output_dir=tmp_path / "esc",
        app="fleet_ops_app",
        write_pdf=False,
    )
    md = artifacts.markdown_path.read_text(encoding="utf-8")
    assert "Aviso temprano" in md or "warn" in md.lower()
    assert "FLEET_OPS_APP" in md
    assert "GOV-FLEET_OPS_APP-BD-001" in md


def test_no_slippage_returns_none(tmp_path, engine):
    """Si no hay slippage · generate() retorna None."""
    _seed_audit_with_old_entries(tmp_path, [
        ("GOV-X-BD-001", "robot", "bd-access", 1),  # solo 1 día · NO slippage
    ])
    artifacts = engine.generate(
        audit_root=tmp_path,
        output_dir=tmp_path / "esc",
        app="robot",
        write_pdf=False,
    )
    assert artifacts is None


def test_request_ids_unique_within_same_day_via_hhmmss(tmp_path, engine):
    """Dos runs el mismo día/app deben generar request_ids distintos (HHMMSS suffix)."""
    import time
    _seed_audit_with_old_entries(tmp_path, [
        ("GOV-FLEET_OPS_APP-BD-001", "fleet_ops_app", "bd-access", 7),
    ])
    a1 = engine.generate(
        audit_root=tmp_path,
        output_dir=tmp_path / "esc",
        app="fleet_ops_app",
        write_pdf=False,
        record_audit=False,  # evitar spam audit
    )
    time.sleep(1.05)  # asegurar HHMMSS distinto
    a2 = engine.generate(
        audit_root=tmp_path,
        output_dir=tmp_path / "esc",
        app="fleet_ops_app",
        write_pdf=False,
        record_audit=False,
    )
    assert a1.request_id != a2.request_id
