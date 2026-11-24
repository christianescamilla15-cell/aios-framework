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
        "hardware-key-request.j2",
        "cmk-request.j2",
        "mailing-list.j2",
        "escalation-email.j2",  # F2 Día 6
    }
    actual = {p.name for p in TEMPLATES_DIR.glob("*.j2")}
    assert expected.issubset(actual), f"Missing: {expected - actual}"


# ── Context Builders ─────────────────────────────────────────────────


def test_for_bd_access_context_includes_team_and_resources(builder):
    ctx = builder.for_bd_access(app="billing", requester_email="alicia.moreno@acme.example")
    assert ctx["app"] == "billing"
    assert ctx["app_display"] == "Billing"
    assert ctx["tier"] == "T0"
    assert ctx["requester"]["email"] == "alicia.moreno@acme.example"
    assert len(ctx["team"]) >= 5  # 5 personas del equipo de entrega
    assert len(ctx["resources"]) >= 3
    assert ctx["multiregion_required"] is True  # T0


def test_for_aws_account_t2_marks_shared(builder):
    ctx = builder.for_aws_account(app="partners", requester_email="alicia.moreno@acme.example")
    assert "compartida" in ctx["account_type"]


def test_for_aws_account_t0_marks_dedicated(builder):
    ctx = builder.for_aws_account(app="billing", requester_email="alicia.moreno@acme.example")
    assert "dedicada" in ctx["account_type"]


def test_for_cmk_returns_5_aliases_per_env(builder):
    ctx = builder.for_cmk(app="billing", requester_email="alicia.moreno@acme.example")
    assert ctx["environments_count"] == 3
    assert len(ctx["cmk_list"]) == 5
    aliases = {item["alias_pattern"] for item in ctx["cmk_list"]}
    assert any("secrets" in a for a in aliases)
    assert any("database" in a for a in aliases)


# ── RequestEngine.generate · E2E ─────────────────────────────────────


def test_generate_bd_access_writes_md(tmp_path, engine):
    artifacts = engine.generate(
        app="billing",
        resource_type="bd-access",
        output_dir=tmp_path / "out",
        requester_email="alicia.moreno@acme.example",
        write_pdf=False,  # PDF requiere weasyprint · keep test fast
        record_audit=True,
        audit_root=tmp_path,
    )
    assert artifacts.markdown_path.exists()
    md = artifacts.markdown_path.read_text(encoding="utf-8")
    assert "Billing" in md
    assert "caracterización" in md  # blocking_block del context
    assert artifacts.request_id.startswith("GOV-BILLING-BD-")
    assert artifacts.audit_entry_recorded is True


def test_generate_creates_audit_entry_with_chain(tmp_path, engine):
    engine.generate(
        app="billing",
        resource_type="bd-access",
        output_dir=tmp_path / "out",
        requester_email="alicia.moreno@acme.example",
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
            app="billing",
            resource_type="not-a-valid-type",
            output_dir=tmp_path / "out",
            requester_email="alicia.moreno@acme.example",
            write_pdf=False,
            record_audit=False,
            audit_root=tmp_path,
        )


def test_generate_hardware_key_uses_correct_template(tmp_path, engine):
    artifacts = engine.generate(
        app="billing",
        resource_type="hardware-key",
        output_dir=tmp_path / "out",
        requester_email="alicia.moreno@acme.example",
        write_pdf=False,
        record_audit=False,
        audit_root=tmp_path,
    )
    assert artifacts.template_used == "hardware-key-request.j2"


def test_generate_aws_account_dedicated_for_t0(tmp_path, engine):
    artifacts = engine.generate(
        app="billing",
        resource_type="aws-account-dedicated",
        output_dir=tmp_path / "out",
        requester_email="alicia.moreno@acme.example",
        write_pdf=False,
        record_audit=False,
        audit_root=tmp_path,
    )
    md = artifacts.markdown_path.read_text(encoding="utf-8")
    assert "Billing" in md
    assert "dedicada" in md
