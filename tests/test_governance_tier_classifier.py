"""Tests · governance.tier_classifier · 9 criterios + 5 reglas + 8 apps (organización ficticia)."""

from __future__ import annotations

import copy

import pytest

from aios.governance.loader import load_rules, reset_cache
from aios.governance.tier_classifier import (
    Tier,
    TierClassifier,
    TierCriteria,
    quick_classify,
)


@pytest.fixture(autouse=True)
def _reset_loader_cache():
    reset_cache()
    yield
    reset_cache()


@pytest.fixture
def classifier():
    return TierClassifier()


@pytest.fixture
def isolated_rules():
    """Reglas mutables por test sin contaminar el singleton."""
    reset_cache()
    rules = load_rules(force_reload=True)
    return copy.deepcopy(rules)


# ── API básica ───────────────────────────────────────────────────────


def test_list_apps_returns_7_in_scope_apps(classifier):
    """Alcance vigente: 7 apps · por omisión se excluye la que está out_of_scope."""
    apps = classifier.list_apps()
    assert len(apps) == 7
    assert "billing" in apps
    assert "partners" in apps
    assert "payments" in apps
    assert "faxgw" not in apps


def test_list_apps_with_include_out_of_scope_returns_8(classifier):
    """include_out_of_scope=True retorna catálogo histórico completo."""
    apps = classifier.list_apps(include_out_of_scope=True)
    assert len(apps) == 8
    assert "faxgw" in apps


def test_classify_unknown_app_returns_error_result(classifier):
    r = classifier.classify("nonexistent_app")
    assert r.declared_tier is None
    assert r.matches is False
    assert "Error" in r.explanation[0]


# ── 8 apps · classification correctness ──────────────────────────────


def test_billing_classifies_t0_correctly(classifier):
    r = classifier.classify("billing")
    assert r.declared_tier == Tier.T0
    assert r.computed_tier == Tier.T0
    assert r.matches is True
    assert r.criteria_evaluated.pci_pii is True
    assert r.criteria_evaluated.continuity_ha == "activo-activo-multiregion"
    assert r.criteria_evaluated.rto_minutes <= 15  # T0 BIA


def test_partners_post_promotion_classifies_t2_correctly(classifier):
    """Promovida de T3 a T2 por manejar PII · debería coincidir con T2."""
    r = classifier.classify("partners")
    assert r.declared_tier == Tier.T2
    assert r.computed_tier == Tier.T2
    assert r.matches is True
    assert r.criteria_evaluated.pci_pii is True


def test_partners_hypothetical_t3_triggers_pii_mismatch(isolated_rules):
    """Caso clave: con PII y declarada T3 · debe FAIL HIGH y sugerir T2."""
    isolated_rules.tiers["assignments"]["partners"]["tier"] = "T3"
    classifier = TierClassifier(rules=isolated_rules)
    r = classifier.classify("partners")
    assert r.declared_tier == Tier.T3
    assert r.matches is False
    assert any(m.rule_id == "TIER_T3_FORBIDS_PII" for m in r.mismatches)
    assert any(m.severity == "HIGH" for m in r.mismatches)
    # suggested_tier debe ser T2 (la regla oficial)
    pii_mm = next(m for m in r.mismatches if m.rule_id == "TIER_T3_FORBIDS_PII")
    assert pii_mm.suggested_tier == Tier.T2


def test_reports_t2_with_review_status_matches(classifier):
    r = classifier.classify("reports")
    assert r.declared_tier == Tier.T2
    assert r.matches is True
    assert r.metadata["tier_status"] == "review_T1"


def test_payments_t0_detects_multiregion_missing(classifier):
    """Payments está declarada T0 pero su expediente NO documenta multi-región
    ni RTO ≤15min · el detector debe marcar ambos HIGH."""
    r = classifier.classify("payments")
    assert r.declared_tier == Tier.T0
    assert not r.matches
    rule_ids = {m.rule_id for m in r.mismatches}
    assert "TIER_T0_REQUIRES_MULTIREGION" in rule_ids


def test_orders_shipping_faxgw_t1_match(classifier):
    for app in ("orders", "shipping", "faxgw"):
        r = classifier.classify(app)
        assert r.declared_tier == Tier.T1, f"{app}: declared mismatch"
        assert r.matches is True, f"{app}: should match · got {r.mismatches}"


def test_support_t2_match(classifier):
    r = classifier.classify("support")
    assert r.declared_tier == Tier.T2
    assert r.matches is True


# ── 9 criterios · inferencia desde rationale ──────────────────────────


def test_pci_pii_detected_from_pci_dss_scope_field(classifier):
    """Payments tiene pci_dss_scope=true · debe inferir pci_pii=True aunque el expediente no diga PII."""
    r = classifier.classify("payments")
    assert r.criteria_evaluated.pci_pii is True


def test_estrategia_decomiso_inferred_from_rationale(isolated_rules):
    """Si rationale menciona 'decomiso' · estrategia=decomiso + vigencia=False."""
    isolated_rules.tiers["assignments"]["support"]["rationale"] = [
        "Bajo impacto · proceso manual",
        "Decomiso aplicativo dentro de 18 meses post-migration",
    ]
    classifier = TierClassifier(rules=isolated_rules)
    r = classifier.classify("support")
    assert r.criteria_evaluated.estrategia_migracion == "decomiso"
    assert r.criteria_evaluated.vigencia_permanent is False


def test_rto_extracted_from_rationale_text(classifier):
    """El expediente de Billing dice 'RTO 15m / RPO 5m' · debe extraerlo."""
    r = classifier.classify("billing")
    assert r.criteria_evaluated.rto_minutes == 15
    assert r.criteria_evaluated.rpo_minutes == 5


# ── reglas de validación ──────────────────────────────────────────────


def test_t0_t1_no_shared_account_detected_when_in_shared(isolated_rules):
    """Forzar BILLING a estar en cuenta compartida T2 · debe FAIL."""
    aws_model = isolated_rules.tiers.setdefault("aws_account_model", {})
    aws_model.setdefault("shared", []).append({
        "name": "test-shared",
        "apps_consolidated": ["Billing"],
    })
    classifier = TierClassifier(rules=isolated_rules)
    r = classifier.classify("billing")
    rule_ids = {m.rule_id for m in r.mismatches}
    assert "TIER_T0_T1_NO_SHARED_ACCOUNT" in rule_ids


def test_t0_rto_bia_detector_triggers_for_payments(classifier):
    r = classifier.classify("payments")
    rule_ids = {m.rule_id for m in r.mismatches}
    assert "TIER_T0_RTO_BIA" in rule_ids


# ── confidence + helpers ──────────────────────────────────────────────


def test_confidence_higher_for_apps_with_more_metadata(classifier):
    """Billing (expediente + multi-región + RTO) ≥ Reports (información parcial)."""
    billing = classifier.classify("billing")
    reports = classifier.classify("reports")
    assert billing.confidence >= reports.confidence


def test_quick_classify_returns_tier_directly():
    assert quick_classify("billing") == Tier.T0
    assert quick_classify("partners") == Tier.T2


def test_explanation_lists_9_criteria(classifier):
    r = classifier.classify("billing")
    text = "\n".join(r.explanation)
    for criterion in (
        "Impacto ingresos",
        "PCI / PII",
        "HA / Continuidad",
        "RTO / RPO",
        "Estrategia migr",
    ):
        assert criterion in text


def test_override_criteria_bypasses_yaml_inference(classifier):
    custom = TierCriteria(
        impact_revenue="bajo",
        impact_service="bajo",
        impact_operation="bajo",
        pci_pii=False,
        vigencia_permanent=True,
        continuity_ha="n/a",
        disponibilidad_target=0.95,
        rto_minutes=1440,
        rpo_minutes=60,
        estrategia_migracion="decomiso",
    )
    r = classifier.classify("billing", override_criteria=custom)
    assert r.criteria_evaluated.pci_pii is False
    assert r.criteria_evaluated.estrategia_migracion == "decomiso"
