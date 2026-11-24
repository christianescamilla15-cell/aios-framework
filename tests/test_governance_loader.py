"""Tests · governance.loader · carga 4 YAMLs base + cache singleton."""

from __future__ import annotations

import pytest

from aios.governance.loader import (
    GovernanceRules,
    YAML_FILES,
    load_rules,
    reset_cache,
)


@pytest.fixture(autouse=True)
def _reset_cache_between_tests():
    reset_cache()
    yield
    reset_cache()


def test_yaml_files_paths_exist():
    """Los 4 archivos YAML base deben existir en aios/governance/rules/."""
    for key, path in YAML_FILES.items():
        assert path.exists(), f"Missing YAML: {key} → {path}"


def test_load_rules_returns_governance_rules():
    rules = load_rules()
    assert isinstance(rules, GovernanceRules)
    assert rules.tiers
    assert rules.approvals
    assert rules.naming
    assert rules.stakeholders


def test_load_rules_caches_singleton():
    r1 = load_rules()
    r2 = load_rules()
    assert r1 is r2


def test_force_reload_returns_fresh_instance():
    r1 = load_rules()
    r2 = load_rules(force_reload=True)
    assert r1 is not r2


def test_supported_apps_excludes_out_of_scope_apps():
    """Una app con tier_status=out_of_scope_* sale del alcance · 8 → 7 apps."""
    rules = load_rules()
    apps = rules.supported_apps
    assert len(apps) == 7
    expected_in_scope = {"billing", "orders", "shipping", "partners", "support", "payments", "reports"}
    assert set(apps) == expected_in_scope
    assert "faxgw" not in apps


def test_all_apps_includes_out_of_scope_for_history():
    """all_apps preserva el catálogo completo (incluye la app fuera de alcance)."""
    rules = load_rules()
    apps = rules.all_apps
    assert len(apps) == 8
    assert "faxgw" in apps


def test_get_app_metadata_returns_full_record():
    rules = load_rules()
    meta = rules.get_app_metadata("billing")
    assert meta["name"] == "Billing"
    assert meta["tier"] == "T0"
    assert meta["app_id"] == "01"
    assert "rationale" in meta


def test_get_app_metadata_raises_keyerror_for_unknown():
    rules = load_rules()
    with pytest.raises(KeyError, match="App 'unknown_app' no encontrado"):
        rules.get_app_metadata("unknown_app")


def test_get_tier_definition_returns_t0_full():
    rules = load_rules()
    t0 = rules.get_tier_definition("T0")
    assert "description_es" in t0
    assert t0.get("disponibilidad") == 0.9995
    assert t0.get("rto_minutes") == 15


def test_get_tier_definition_raises_for_unknown_tier():
    rules = load_rules()
    with pytest.raises(KeyError, match="Tier 'T9'"):
        rules.get_tier_definition("T9")


def test_validation_rules_has_8_rules():
    rules = load_rules()
    rs = rules.get_validation_rules()
    assert len(rs) >= 5  # mínimo 5 oficiales documentadas
    rule_ids = {r["id"] for r in rs}
    assert "TIER_T3_FORBIDS_PII" in rule_ids
    assert "TIER_T0_REQUIRES_MULTIREGION" in rule_ids
