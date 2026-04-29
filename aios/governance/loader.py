"""AIOS Governance · loader.py · carga los 4 YAMLs base de governance.

Lazy-loaded singleton · cache en memoria · raises clear errors si YAML inválido.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Constants · paths a los 4 YAMLs base
# ---------------------------------------------------------------------------

RULES_DIR = Path(__file__).parent / "rules"

YAML_FILES = {
    "tiers": RULES_DIR / "tiers.yaml",
    "approvals": RULES_DIR / "approvals.yaml",
    "naming": RULES_DIR / "naming.yaml",
    "stakeholders": RULES_DIR / "stakeholders.yaml",
}


# ---------------------------------------------------------------------------
# GovernanceRulesLoader · API principal
# ---------------------------------------------------------------------------

@dataclass
class GovernanceRules:
    """Container con las 4 reglas cargadas."""
    tiers: dict[str, Any]
    approvals: dict[str, Any]
    naming: dict[str, Any]
    stakeholders: dict[str, Any]

    @property
    def supported_apps(self) -> list[str]:
        """Las 8 apps Revenue Accounting."""
        return list(self.tiers.get("assignments", {}).keys())

    def get_app_metadata(self, app: str) -> dict[str, Any]:
        """Metadata del aplicativo desde tiers.yaml.assignments."""
        assignments = self.tiers.get("assignments", {})
        if app not in assignments:
            raise KeyError(
                f"App '{app}' no encontrado en tiers.yaml. "
                f"Apps soportados: {sorted(assignments.keys())}"
            )
        return assignments[app]

    def get_tier_definition(self, tier: str) -> dict[str, Any]:
        """Definición completa de un TIER (T0/T1/T2/T3)."""
        tiers_def = self.tiers.get("tiers", {})
        if tier not in tiers_def:
            raise KeyError(f"Tier '{tier}' no encontrado · esperados: T0/T1/T2/T3")
        return tiers_def[tier]

    def get_validation_rules(self) -> list[dict[str, Any]]:
        """Lista de reglas de validación TIER."""
        return self.tiers.get("validation_rules", [])

    def get_naming_pattern(self, kind: str) -> dict[str, Any]:
        """Pattern de naming · kind ∈ iam_role_naming · repo_naming · cmk_naming · secret_naming · branch_naming."""
        if kind not in self.naming:
            valid = [k for k in self.naming if k.endswith("_naming")]
            raise KeyError(f"Naming kind '{kind}' no encontrado · esperados: {valid}")
        return self.naming[kind]

    def get_app_prefixes(self) -> dict[str, dict[str, str]]:
        """AppPrefixes oficiales · 8 apps."""
        return self.naming.get("app_prefixes", {})


# Singleton para evitar releer los YAMLs en cada llamada
_cached_rules: GovernanceRules | None = None


def load_rules(force_reload: bool = False) -> GovernanceRules:
    """Carga (o retorna cache) las 4 reglas de governance.

    Args:
        force_reload: Si True · recarga desde disco aunque haya cache.

    Returns:
        GovernanceRules con tiers · approvals · naming · stakeholders.

    Raises:
        FileNotFoundError si algún YAML falta.
        yaml.YAMLError si syntax inválida.
    """
    global _cached_rules

    if _cached_rules is not None and not force_reload:
        return _cached_rules

    loaded: dict[str, Any] = {}
    for key, path in YAML_FILES.items():
        if not path.exists():
            raise FileNotFoundError(
                f"Rule YAML missing: {path}. "
                "Verify aios.governance.rules/ está poblado correctamente."
            )
        with path.open("r", encoding="utf-8") as f:
            loaded[key] = yaml.safe_load(f)

    _cached_rules = GovernanceRules(
        tiers=loaded["tiers"],
        approvals=loaded["approvals"],
        naming=loaded["naming"],
        stakeholders=loaded["stakeholders"],
    )
    return _cached_rules


def reset_cache() -> None:
    """Limpia el cache · útil para tests."""
    global _cached_rules
    _cached_rules = None
