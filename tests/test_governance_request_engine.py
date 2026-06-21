"""Tests · governance.request_engine · 5 templates + render MD + audit entry."""

from __future__ import annotations

from pathlib import Path

import pytest

from aios.governance.audit_trail import AuditTrail, default_audit_path
from aios.governance.loader import load_rules, reset_cache
from aios.governance.request_engine import (
    ContextBuilder,
    RequestEngine,
    TEMPLATES_DIR,
)


@pytest.fixture(autouse=True)
def _reset_cache():
    reset_cache()
    yield
    reset_cache()


@pytest.fixture
def engine():
    return RequestEngine(load_rules())


@pytest.fixture
def builder():
    return ContextBuilder(load_rules())


# ── Templates ────────────────────────────────────────────────────────


def test_5_jinja2_templates_present():
    """Los 5 templates oficiales deben existir."""
    expected = {
        "bd-access.j2",
        "aws-account.j2",
        "yubikey-request.j2",
        "cmk-request.j2",
        "dl-inclusion.j2",
        "escalation-email.j2",  # F2 Día 6
    }
    actual = {p.name for p in TEMPLATES_DIR.glob("*.j2")}
    assert expected.issubset(actual), f"Missing: {expected - actual}"


# ── Context Builders ─────────────────────────────────────────────────


def test_for_bd_access_context_includes_team_and_resources(builder):
    ctx = builder.for_bd_access(app="fleet_ops_app", requester_email="engineer@acmeair.com")
    assert ctx["app"] == "fleet_ops_app"
    assert ctx["app_display"] == "FLEET_OPS_APP"
    assert ctx["tier"] == "T0"
    assert ctx["requester"]["email"] == "engineer@acmeair.com"
    assert len(ctx["team"]) >= 5  # 5 eTribe miembros
    assert len(ctx["resources"]) >= 3
    assert ctx["multiregion_required"] is True  # T0


def test_for_aws_account_t2_marks_shared(builder):
    ctx = builder.for_aws_account(app="srg", requester_email="engineer@acmeair.com")
    assert "compartida" in ctx["account_type"]


def test_for_aws_account_t0_marks_dedicated(builder):
    ctx = builder.for_aws_account(app="fleet_ops_app", requester_email="engineer@acmeair.com")
    assert "dedicada" in ctx["account_type"]


def test_for_cmk_returns_5_aliases_per_env(builder):
    ctx = builder.for_cmk(app="fleet_ops_app", requester_email="engineer@acmeair.com")
    assert ctx["environments_count"] == 3
    assert len(ctx["cmk_list"]) == 5
    aliases = {item["alias_pattern"] for item in ctx["cmk_list"]}
    assert any("secrets" in a for a in aliases)
    assert any("aurora" in a for a in aliases)


# ── RequestEngine.generate · E2E ─────────────────────────────────────


def test_generate_bd_access_writes_md(tmp_path, engine):
    artifacts = engine.generate(
        app="fleet_ops_app",
        resource_type="bd-access",
        output_dir=tmp_path / "out",
        requester_email="engineer@acmeair.com",
        write_pdf=False,  # PDF requiere weasyprint · keep test fast
        record_audit=True,
        audit_root=tmp_path,
    )
    assert artifacts.markdown_path.exists()
    md = artifacts.markdown_path.read_text(encoding="utf-8")
    assert "FLEET_OPS_APP" in md
    assert "Block 4" in md  # blocking_block del context
    assert artifacts.request_id.startswith("GOV-FLEET_OPS_APP-BD-")
    assert artifacts.audit_entry_recorded is True


def test_generate_creates_audit_entry_with_chain(tmp_path, engine):
    engine.generate(
        app="fleet_ops_app",
        resource_type="bd-access",
        output_dir=tmp_path / "out",
        requester_email="engineer@acmeair.com",
        write_pdf=False,
        record_audit=True,
        audit_root=tmp_path,
    )
    audit_path = default_audit_path(tmp_path)
    assert audit_path.exists()
    trail = AuditTrail(audit_path)
    intact, errors = trail.verify_chain()
    assert intact, errors


def test_generate_invalid_resource_type_raises(tmp_path, engine):
    with pytest.raises(ValueError, match="resource_type"):
        engine.generate(
            app="fleet_ops_app",
            resource_type="not-a-valid-type",
            output_dir=tmp_path / "out",
            requester_email="engineer@acmeair.com",
            write_pdf=False,
            record_audit=False,
            audit_root=tmp_path,
        )


def test_generate_yubikey_uses_correct_template(tmp_path, engine):
    artifacts = engine.generate(
        app="fleet_ops_app",
        resource_type="yubikey-request",
        output_dir=tmp_path / "out",
        requester_email="engineer@acmeair.com",
        write_pdf=False,
        record_audit=False,
        audit_root=tmp_path,
    )
    assert artifacts.template_used == "yubikey-request.j2"


def test_generate_aws_account_dedicated_for_t0(tmp_path, engine):
    artifacts = engine.generate(
        app="fleet_ops_app",
        resource_type="aws-account-dedicated",
        output_dir=tmp_path / "out",
        requester_email="engineer@acmeair.com",
        write_pdf=False,
        record_audit=False,
        audit_root=tmp_path,
    )
    md = artifacts.markdown_path.read_text(encoding="utf-8")
    assert "FLEET_OPS_APP" in md
