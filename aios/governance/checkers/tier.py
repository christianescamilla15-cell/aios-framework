"""TierChecker · valida la asignación de TIER contra los criterios de rules/tiers.yaml.

Detecta:
  - TIER_T3_FORBIDS_PII
  - TIER_T0_T1_NO_SHARED_ACCOUNT
  - TIER_T0_REQUIRES_MULTIREGION (heurística sobre archivos CDK)
  - TIER_T0_RTO_BIA (heurística · busca BIA*.md)
  - TIER_RECLASSIFICATION_PENDING (informativo)
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from ..loader import GovernanceRules
from ..models import CheckSeverity, GovernanceFinding
from .naming import EXCLUDED_DIRS

# Región de AWS (p. ej. us-east-1, eu-west-3) y construcciones globales que implican multirregión
_REGION_RE = re.compile(r"\b(?:us|eu|ap|sa|ca|me|af|mx|il)-(?:east|west|north|south|central|northeast|southeast|northwest|southwest)-\d\b")
_GLOBAL_CONSTRUCT_RE = re.compile(r"GlobalCluster|global_table|GlobalTable|cross_region|replica_regions|crossRegion", re.IGNORECASE)


def _walk_files(root: Path, name_match) -> list[Path]:
    """Walk filtrando dirnames in-place · poda EXCLUDED_DIRS al descender."""
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for fname in filenames:
            if name_match(fname):
                found.append(Path(dirpath) / fname)
                if len(found) >= 50:  # cap defensivo
                    return found
    return found


class TierChecker:
    """Valida que el TIER declared del aplicativo coincide con los 9 criterios oficiales."""

    def __init__(self, rules: GovernanceRules):
        self._rules = rules

    def check(self, root: Path, app: str) -> list[GovernanceFinding]:
        findings: list[GovernanceFinding] = []
        try:
            metadata = self._rules.get_app_metadata(app)
        except KeyError as e:
            findings.append(GovernanceFinding(
                rule_id="GOV-APP-NOT-FOUND",
                severity=CheckSeverity.CRITICAL,
                category="tier",
                message=str(e),
            ))
            return findings

        declared_tier = metadata.get("tier", "").split()[0]  # ej. "T2 (T3→T2 propuesto)" → "T2"

        # Regla 1 · T3 prohíbe PII
        if declared_tier == "T3" and metadata.get("rationale"):
            for r in metadata["rationale"]:
                if "PII" in r and ("Sí" in r or "Si" in r):
                    findings.append(GovernanceFinding(
                        rule_id="TIER_T3_FORBIDS_PII",
                        severity=CheckSeverity.FAIL,
                        category="tier",
                        message=(
                            f"App '{app}' declared T3 pero rationale incluye PII Sí. "
                            "tiers.yaml dice T3 = PCI/PII NO."
                        ),
                        suggestion="Promover a T2 como mínimo (reclasificación de TIER)",
                    ))
                    break

        # Regla 2 · T0/T1 NO comparten cuenta AWS
        if declared_tier in ("T0", "T1"):
            aws_model = self._rules.tiers.get("aws_account_model", {})
            shared = aws_model.get("shared", [])
            for s in shared:
                if app in s.get("apps_consolidated", []):
                    findings.append(GovernanceFinding(
                        rule_id="TIER_T0_T1_NO_SHARED_ACCOUNT",
                        severity=CheckSeverity.FAIL,
                        category="tier",
                        message=(
                            f"App '{app}' declared {declared_tier} pero está en cuenta T2 compartida. "
                            "T0/T1 requieren cuenta dedicada."
                        ),
                    ))

        # Regla 3 · T0 requires multi-region (heurística · revisa CDK: dos regiones distintas o
        # una construcción global)
        if declared_tier == "T0":
            cdk_files = _walk_files(
                root,
                lambda f: (f.startswith("cdk") and f.endswith(".py")) or f.endswith("_stack.py"),
            )
            multiregion_found = False
            for f in cdk_files[:30]:  # límite por performance
                try:
                    text = f.read_text(encoding="utf-8", errors="ignore")
                    regions = set(_REGION_RE.findall(text))
                    if len(regions) >= 2 or _GLOBAL_CONSTRUCT_RE.search(text):
                        multiregion_found = True
                        break
                except Exception:
                    continue

            if not multiregion_found and cdk_files:
                findings.append(GovernanceFinding(
                    rule_id="TIER_T0_REQUIRES_MULTIREGION",
                    severity=CheckSeverity.WARN,
                    category="tier",
                    message=(
                        f"App '{app}' es T0 pero no se detectó configuración multi-región "
                        "en archivos CDK (dos regiones o una construcción global)."
                    ),
                    suggestion="Declarar activo-activo en dos regiones (p. ej. base de datos global)",
                ))

        # Regla 4 · el RTO del BIA no supera el del TIER T0 (heurística · busca BIA*.md)
        max_rto = int(self._rules.tiers.get("tiers", {}).get("T0", {}).get("rto_minutes", 15))
        if declared_tier == "T0":
            bia_files = _walk_files(
                root,
                lambda f: f.upper().startswith("BIA") and f.endswith(".md"),
            )
            for bia in bia_files[:5]:
                try:
                    text = bia.read_text(encoding="utf-8", errors="ignore")
                    rto_match = re.search(r"RTO[\s:]+(\d+)\s*(min|m\b|h|hour)", text, re.IGNORECASE)
                    if rto_match:
                        value = int(rto_match.group(1))
                        unit = rto_match.group(2).lower()
                        rto_min = value * 60 if unit.startswith("h") else value
                        if rto_min > max_rto:
                            findings.append(GovernanceFinding(
                                rule_id="TIER_T0_RTO_BIA",
                                severity=CheckSeverity.WARN,
                                category="tier",
                                message=(
                                    f"BIA declarado RTO={rto_min}min · T0 exige ≤ {max_rto} min."
                                ),
                                location=str(bia.relative_to(root)),
                            ))
                except Exception:
                    continue

        # Regla 5 · informativo · estado de re-clasificación pending
        status = metadata.get("tier_status", "confirmed")
        if status in ("review_T0", "review_T1", "promoted_from_T3", "promoted_from_T2"):
            findings.append(GovernanceFinding(
                rule_id="TIER_RECLASSIFICATION_PENDING",
                severity=CheckSeverity.WARN,
                category="tier",
                message=(
                    f"App '{app}' tier_status='{status}' · re-clasificación pendiente firma."
                ),
                suggestion="Confirmar la reclasificación con la cadena tier_reclassification (approvals.yaml)",
            ))

        # PASS final · si no hay findings de severity FAIL+
        if not any(f.severity in (CheckSeverity.FAIL, CheckSeverity.CRITICAL) for f in findings):
            findings.append(GovernanceFinding(
                rule_id="TIER_ASSIGNMENT_OK",
                severity=CheckSeverity.PASS,
                category="tier",
                message=f"App '{app}' tier '{declared_tier}' coincide con los criterios de tiers.yaml",
            ))

        return findings
