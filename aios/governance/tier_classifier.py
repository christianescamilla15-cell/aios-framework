"""AIOS Governance · TierClassifier · clasificación de aplicativos por TIER (9 criterios oficiales AMX).

Aplica los criterios de Tiers 2.xlsx · sheet Tier_definicion · equipo Domini.
Detecta mismatches (caso SRG: declared T3 pero PII Sí → debería ser T2).

F2 Día 7 · 29-abr-2026 · implementación real.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

from .loader import GovernanceRules, load_rules


# ---------------------------------------------------------------------------
# Tipos y enums
# ---------------------------------------------------------------------------

class Tier(str, Enum):
    T0 = "T0"
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"


ImpactLevel = Literal["alto", "medio", "bajo", "muy_bajo"]


@dataclass
class TierCriteria:
    """9 criterios oficiales AMX para clasificación TIER."""

    impact_revenue: ImpactLevel = "bajo"
    impact_service: ImpactLevel = "bajo"
    impact_operation: ImpactLevel = "bajo"
    pci_pii: bool = False
    vigencia_permanent: bool = True
    continuity_ha: str = "n/a"  # "activo-activo-multiregion" · "activo-pasivo-multiregion" · etc.
    disponibilidad_target: float = 0.95
    rto_minutes: int = 1440  # default 1 día
    rpo_minutes: int = 60
    estrategia_migracion: Literal["refactoring", "replatform", "relocate", "decomiso"] = "refactoring"


@dataclass
class TierMismatch:
    """Resultado de detección de mismatch entre declared TIER y criterios."""
    declared_tier: Tier
    suggested_tier: Tier
    reason: str
    severity: Literal["HIGH", "MEDIUM", "LOW"]
    rule_id: str


@dataclass
class TierClassificationResult:
    """Output completo del classifier."""
    app: str
    declared_tier: Tier | None
    computed_tier: Tier
    confidence: float
    matches: bool
    mismatches: list[TierMismatch] = field(default_factory=list)
    criteria_evaluated: TierCriteria | None = None
    explanation: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# TierClassifier · core engine
# ---------------------------------------------------------------------------

class TierClassifier:
    """Clasifica aplicativos según 9 criterios oficiales AMX.

    Carga reglas desde aios/governance/rules/tiers.yaml + heurísticas sobre
    el campo `rationale` (texto libre validado en sesión 28-abr).
    """

    # Severidad → orden ascendente
    TIER_ORDER = {Tier.T3: 0, Tier.T2: 1, Tier.T1: 2, Tier.T0: 3}

    def __init__(self, rules: GovernanceRules | None = None):
        self._rules = rules or load_rules()

    # -----------------------------------------------------------------------
    # API pública
    # -----------------------------------------------------------------------

    def list_apps(self) -> list[str]:
        return sorted(self._rules.tiers.get("assignments", {}).keys())

    def classify(
        self,
        app: str,
        override_criteria: TierCriteria | None = None,
    ) -> TierClassificationResult:
        try:
            meta = self._rules.get_app_metadata(app)
        except KeyError as e:
            return TierClassificationResult(
                app=app,
                declared_tier=None,
                computed_tier=Tier.T3,
                confidence=0.0,
                matches=False,
                explanation=[f"Error: {e}"],
            )

        # Declared tier · puede ser "T2 (T3→T2 propuesto)" → primer token
        declared_str = (meta.get("tier") or "").split()[0]
        try:
            declared = Tier(declared_str)
        except ValueError:
            declared = None

        criteria = override_criteria or self._infer_criteria(meta)
        mismatches = self._evaluate_rules(criteria=criteria, declared=declared, meta=meta)

        # Computed tier · empieza con declared y baja según violations
        computed = declared or Tier.T3
        if mismatches:
            # Tomar el suggested_tier del mismatch más severo
            high = [m for m in mismatches if m.severity == "HIGH"]
            if high:
                computed = high[0].suggested_tier

        confidence = self._compute_confidence(criteria, meta, mismatches)
        matches = computed == declared and not any(m.severity == "HIGH" for m in mismatches)

        explanation = self._build_explanation(meta, criteria, declared, computed, mismatches)

        return TierClassificationResult(
            app=app,
            declared_tier=declared,
            computed_tier=computed,
            confidence=confidence,
            matches=matches,
            mismatches=mismatches,
            criteria_evaluated=criteria,
            explanation=explanation,
            metadata={
                "name": meta.get("name", app),
                "description": meta.get("description", ""),
                "tier_status": meta.get("tier_status", "confirmed"),
                "owner_etribe": meta.get("owner_etribe", "?"),
                "owner_amx": meta.get("owner_amx", "?"),
            },
        )

    # -----------------------------------------------------------------------
    # Inferencia de criterios desde rationale (texto libre)
    # -----------------------------------------------------------------------

    @staticmethod
    def _infer_criteria(meta: dict[str, Any]) -> TierCriteria:
        """Deduce los 9 criterios analizando rationale + structured fields.

        Reglas heurísticas calibradas con los 8 aplicativos del programa:
          - 'PII Sí' / 'PCI Sí' / 'pci_dss_scope=true' → pci_pii=True
          - 'Alto impacto ingresos' / 'orquestador' → impact_revenue=alto
          - 'multi-región' / 'Activo-Activo' → continuity_ha
          - 'BIA RTO Xmin' → rto_minutes
          - 'EOL' / 'decomiso' → estrategia_migracion
        """
        rationale = " ".join(meta.get("rationale", []))
        rationale_lower = rationale.lower()

        # 4 · PCI/PII · KEY (descalifica T3)
        pci_pii = (
            "pii sí" in rationale_lower
            or "pci sí" in rationale_lower
            or "pci/pii sí" in rationale_lower
            or meta.get("pci_dss_scope") is True
        )

        # 1 · Impacto revenue
        if "alto impacto ingresos" in rationale_lower or "orquestador" in rationale_lower:
            impact_revenue: ImpactLevel = "alto"
        elif "medio-alto impacto" in rationale_lower or "medio impacto ingresos" in rationale_lower:
            impact_revenue = "medio"
        elif "bajo-medio impacto" in rationale_lower or "bajo impacto" in rationale_lower:
            impact_revenue = "bajo"
        else:
            impact_revenue = "muy_bajo"

        # 6 · HA / Continuidad
        if "activo-activo" in rationale_lower and (
            "multirregión" in rationale_lower or "multi-región" in rationale_lower
            or "virginia" in rationale_lower or "oregon" in rationale_lower
        ):
            continuity = "activo-activo-multiregion"
        elif "activo-pasivo" in rationale_lower and ("multi" in rationale_lower or "región" in rationale_lower):
            continuity = "activo-pasivo-multiregion"
        elif "multizona" in rationale_lower or "multi-zona" in rationale_lower:
            continuity = "activo-activo-multizona"
        else:
            continuity = "n/a"

        # 8 · RTO/RPO desde "BIA exige RTO Xm" / "RTO ≤ Y"
        rto_match = re.search(r"rto[\s≤<=:]*(\d+)\s*(min|m\b|h|hour)", rationale_lower)
        if rto_match:
            value = int(rto_match.group(1))
            unit = rto_match.group(2)
            rto_min = value * 60 if unit.startswith("h") else value
        else:
            rto_min = 1440  # 1 día default

        rpo_match = re.search(r"rpo[\s≤<=:]*(\d+)\s*(min|m\b|h|hour)", rationale_lower)
        if rpo_match:
            value = int(rpo_match.group(1))
            unit = rpo_match.group(2)
            rpo_min = value * 60 if unit.startswith("h") else value
        else:
            rpo_min = 60

        # 9 · Estrategia migración
        if "decomiso" in rationale_lower:
            estrategia: Literal["refactoring", "replatform", "relocate", "decomiso"] = "decomiso"
        elif "replatform" in rationale_lower:
            estrategia = "replatform"
        elif "relocate" in rationale_lower:
            estrategia = "relocate"
        else:
            estrategia = "refactoring"

        # 5 · Vigencia
        vigencia_permanent = estrategia != "decomiso"

        # 7 · Disponibilidad target · derivado del declared tier (best effort)
        # Sin información cuantitativa explícita lo dejamos en default 0.95
        disponibilidad = 0.95

        return TierCriteria(
            impact_revenue=impact_revenue,
            impact_service=impact_revenue,  # heurística simple
            impact_operation=impact_revenue,
            pci_pii=pci_pii,
            vigencia_permanent=vigencia_permanent,
            continuity_ha=continuity,
            disponibilidad_target=disponibilidad,
            rto_minutes=rto_min,
            rpo_minutes=rpo_min,
            estrategia_migracion=estrategia,
        )

    # -----------------------------------------------------------------------
    # Evaluación de reglas
    # -----------------------------------------------------------------------

    def _evaluate_rules(
        self,
        criteria: TierCriteria,
        declared: Tier | None,
        meta: dict[str, Any],
    ) -> list[TierMismatch]:
        if declared is None:
            return []

        mismatches: list[TierMismatch] = []

        # Regla 1 · TIER_T3_FORBIDS_PII (caso SRG)
        m = self._check_t3_pii_mismatch(criteria, declared)
        if m:
            mismatches.append(m)

        # Regla 2 · cuenta dedicada · usa aws_account_model.shared
        shared = self._is_in_shared_account(meta)
        m = self._check_t0_t1_no_shared_account(criteria, declared, shared)
        if m:
            mismatches.append(m)

        # Regla 3 · multi-región para T0
        m = self._check_t0_multiregion(criteria, declared)
        if m:
            mismatches.append(m)

        # Regla 4 · BIA RTO ≤ 10min para T0
        m = self._check_t0_bia_rto(criteria, declared, criteria.rto_minutes)
        if m:
            mismatches.append(m)

        # Regla 5 · TIER_T3_DECOMISO_18MONTHS · informativo si declared T3 + permanente
        if declared == Tier.T3 and criteria.vigencia_permanent and criteria.estrategia_migracion != "decomiso":
            mismatches.append(TierMismatch(
                declared_tier=Tier.T3,
                suggested_tier=Tier.T2,
                reason=(
                    "T3 implica decomiso ≤18 meses · este aplicativo está marcado como permanente "
                    "sin estrategia de decomiso · revisar tier_status"
                ),
                severity="LOW",
                rule_id="TIER_T3_DECOMISO_18MONTHS",
            ))

        return mismatches

    def _is_in_shared_account(self, meta: dict[str, Any]) -> bool:
        aws_model = self._rules.tiers.get("aws_account_model", {})
        shared = aws_model.get("shared", [])
        app_name = (meta.get("name") or "").lower()
        for cuenta in shared:
            apps = [a.lower() for a in cuenta.get("apps_consolidated", [])]
            if app_name in apps:
                return True
        return False

    @staticmethod
    def _check_t3_pii_mismatch(criteria: TierCriteria, declared: Tier) -> TierMismatch | None:
        if declared == Tier.T3 and criteria.pci_pii:
            return TierMismatch(
                declared_tier=Tier.T3,
                suggested_tier=Tier.T2,
                reason=(
                    "T3 prohíbe PCI/PII por definición (tabla oficial AMX). "
                    "Aplicativo maneja datos personales · debe ser T2 mínimo."
                ),
                severity="HIGH",
                rule_id="TIER_T3_FORBIDS_PII",
            )
        return None

    @staticmethod
    def _check_t0_t1_no_shared_account(
        criteria: TierCriteria,
        declared: Tier,
        shared: bool,
    ) -> TierMismatch | None:
        if declared in (Tier.T0, Tier.T1) and shared:
            return TierMismatch(
                declared_tier=declared,
                suggested_tier=declared,
                reason=(
                    f"{declared.value} declared en cuenta T2 compartida · requiere cuenta dedicada"
                ),
                severity="HIGH",
                rule_id="TIER_T0_T1_NO_SHARED_ACCOUNT",
            )
        return None

    @staticmethod
    def _check_t0_multiregion(criteria: TierCriteria, declared: Tier) -> TierMismatch | None:
        if declared == Tier.T0 and criteria.continuity_ha != "activo-activo-multiregion":
            return TierMismatch(
                declared_tier=Tier.T0,
                suggested_tier=Tier.T0,
                reason=(
                    "T0 requiere Activo-Activo multi-región · setup actual: "
                    f"{criteria.continuity_ha} · ADR-002 v2 exige Virginia + Oregon"
                ),
                severity="HIGH",
                rule_id="TIER_T0_REQUIRES_MULTIREGION",
            )
        return None

    @staticmethod
    def _check_t0_bia_rto(
        criteria: TierCriteria,
        declared: Tier,
        bia_rto_min: int,
    ) -> TierMismatch | None:
        if declared == Tier.T0 and bia_rto_min > 15:
            return TierMismatch(
                declared_tier=Tier.T0,
                suggested_tier=Tier.T1 if bia_rto_min <= 30 else Tier.T2,
                reason=f"BIA declarado RTO={bia_rto_min}min · T0 exige ≤10-15min",
                severity="HIGH",
                rule_id="TIER_T0_RTO_15MIN_BIA",
            )
        return None

    # -----------------------------------------------------------------------
    # Confidence + explanation
    # -----------------------------------------------------------------------

    @staticmethod
    def _compute_confidence(
        criteria: TierCriteria,
        meta: dict[str, Any],
        mismatches: list[TierMismatch],
    ) -> float:
        """Confianza basada en cantidad de info structurada disponible."""
        score = 0.5  # base
        if meta.get("rationale"):
            score += 0.2
        if meta.get("pci_dss_scope") is not None:
            score += 0.1
        if meta.get("custody"):
            score += 0.05
        if criteria.continuity_ha != "n/a":
            score += 0.1
        if criteria.rto_minutes < 1440:
            score += 0.05
        # Penalizar si hay HIGH mismatches (indica que la info original era inconsistente)
        high_count = sum(1 for m in mismatches if m.severity == "HIGH")
        score -= 0.1 * high_count
        return max(0.0, min(1.0, score))

    def _build_explanation(
        self,
        meta: dict[str, Any],
        criteria: TierCriteria,
        declared: Tier | None,
        computed: Tier,
        mismatches: list[TierMismatch],
    ) -> list[str]:
        lines = [
            f"Aplicativo: {meta.get('name', '?')} · {meta.get('description', '')}",
            f"TIER declared: {declared.value if declared else '?'} (tier_status={meta.get('tier_status', '?')})",
            f"TIER computed: {computed.value}",
            "",
            "Criterios oficiales AMX (9):",
            f"  1. Impacto ingresos:   {criteria.impact_revenue}",
            f"  2. Impacto servicio:   {criteria.impact_service}",
            f"  3. Impacto operación:  {criteria.impact_operation}",
            f"  4. PCI / PII:          {'Sí' if criteria.pci_pii else 'No'}  ← KEY (T3 sólo si NO)",
            f"  5. Vigencia:           {'permanente' if criteria.vigencia_permanent else 'decomiso 18m'}",
            f"  6. HA / Continuidad:   {criteria.continuity_ha}",
            f"  7. Disponibilidad:     {criteria.disponibilidad_target:.4f}",
            f"  8. RTO / RPO (min):    {criteria.rto_minutes} / {criteria.rpo_minutes}",
            f"  9. Estrategia migr:    {criteria.estrategia_migracion}",
        ]

        if mismatches:
            lines.append("")
            lines.append("Mismatches detectados:")
            for m in mismatches:
                lines.append(f"  · [{m.severity}] {m.rule_id}: {m.reason}")
                lines.append(f"        → suggested: {m.suggested_tier.value}")
        else:
            lines.append("")
            lines.append("✓ Sin mismatches detectados · TIER coherente con criterios.")

        return lines


# ---------------------------------------------------------------------------
# Helpers de conveniencia
# ---------------------------------------------------------------------------

def quick_classify(app: str) -> Tier:
    return TierClassifier().classify(app).computed_tier


def is_tier_mismatch(app: str) -> bool:
    return not TierClassifier().classify(app).matches
