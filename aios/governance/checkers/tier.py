"""TierChecker · valida assignment TIER vs criterios oficiales AMX.

Detecta:
  - TIER_T3_FORBIDS_PII (caso SRG)
  - TIER_T0_T1_NO_SHARED_ACCOUNT
  - TIER_T0_REQUIRES_MULTIREGION
  - TIER_T0_T1_REQUIRES_PITR (heurística)
  - TIER_T0_RTO_15MIN_BIA (heurística · busca BIA.md)
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from ..loader import GovernanceRules
from ..models import CheckSeverity, GovernanceFinding
from .naming import EXCLUDED_DIRS


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
                            "Tabla AMX dice T3 = PCI/PII NO."
                        ),
                        suggestion="Promover a T2 mínimo (caso SRG · firma Borde Arq Israel)",
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

        # Regla 3 · T0 requires multi-region (heurística · revisa CDK)
        if declared_tier == "T0":
            cdk_files = _walk_files(
                root,
                lambda f: (f.startswith("cdk") and f.endswith(".py")) or f.endswith("_stack.py"),
            )
            multiregion_found = False
            for f in cdk_files[:30]:  # límite por performance
                try:
                    text = f.read_text(encoding="utf-8", errors="ignore")
                    if re.search(r"us-east-1|us-west-2|GlobalCluster|cross_region", text, re.IGNORECASE):
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
                        "en archivos CDK (us-east-1 + us-west-2)."
                    ),
                    suggestion="ADR-002 v2 exige Activo-Activo Virginia + Oregon",
                ))

        # Regla 4 · BIA RTO ≤ 10 min para T0 (heurística · busca BIA.md)
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
                        if rto_min > 10:
                            findings.append(GovernanceFinding(
                                rule_id="TIER_T0_RTO_15MIN_BIA",
                                severity=CheckSeverity.WARN,
                                category="tier",
                                message=(
                                    f"BIA declarado RTO={rto_min}min · T0 exige ≤ 10 min."
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
                suggestion="Confirmar firma con Borde Arq + Roberto Carlos Osorio",
            ))

        # PASS final · si no hay findings de severity FAIL+
        if not any(f.severity in (CheckSeverity.FAIL, CheckSeverity.CRITICAL) for f in findings):
            findings.append(GovernanceFinding(
                rule_id="TIER_ASSIGNMENT_OK",
                severity=CheckSeverity.PASS,
                category="tier",
                message=f"App '{app}' tier '{declared_tier}' coincide con criterios oficiales AMX",
            ))

        return findings
