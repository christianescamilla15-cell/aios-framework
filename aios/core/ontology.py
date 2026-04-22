"""Domain Ontology · v1.8.0 · RFC-003 Nivel 1

Classifica security findings ANTES del auto-fix · distingue:
- bug            · CWE claro · auto_fix OK
- business_rule  · intent del dominio · NO auto_fix · pausar y reportar
- migration_candidate · migración conocida con fix_template
- unclear        · requiere humano · warning pero no bloquea

Diseño intencional:
- YAML externo (no hardcoded en Python) · los dueños del dominio editan el
  catálogo sin tocar código del framework.
- Matching por regex O literal · escalable.
- Default policy configurable (strict · bug · unclear) para backwards compat.

Uso canónico:
    ontology = load_ontology(Path("aios/policies/amx-revenue-accounting/ontology.yaml"))
    result = classify_finding(finding, ontology)
    if result.action == "pause_for_review":
        print(f"REQUIERE REVIEW · {result.message}")
    elif result.action == "auto_fix":
        apply_fix(finding, result.fix_template)

Catálogo canónico AMX en:
    aios/policies/amx-revenue-accounting/ontology.yaml

Deriva de RFC-003 del BACKLOG · feedback LM-FRK70K 2026-04-22.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Acciones posibles al classificar un finding
ACTION_AUTO_FIX = "auto_fix"
ACTION_PAUSE_FOR_REVIEW = "pause_for_review"
ACTION_SKIP = "skip"
ACTION_WARN = "warn"

VALID_ACTIONS = (ACTION_AUTO_FIX, ACTION_PAUSE_FOR_REVIEW, ACTION_SKIP, ACTION_WARN)


@dataclass
class ClassificationResult:
    """Resultado de classificar un finding contra el domain ontology."""
    action: str  # auto_fix | pause_for_review | skip | warn
    ontology_match: Optional[str] = None  # id del pattern que matcheo
    classification: str = "unclear"  # bug | business_rule | migration_candidate | unclear
    message: str = ""
    fix_template: Optional[str] = None
    evidence_required: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


def load_ontology(path: Path) -> dict:
    """Carga ontology YAML. Retorna dict vacio si no existe (no-op safe)."""
    if not path.exists():
        return {
            "version": "1.0",
            "patterns": [],
            "default_classification": "unclear",
            "default_action": ACTION_AUTO_FIX,  # backwards compat v1.7.x
        }
    try:
        import yaml
    except ImportError:
        # Graceful degrade si PyYAML no esta instalado
        return {
            "version": "1.0",
            "patterns": [],
            "default_classification": "unclear",
            "default_action": ACTION_AUTO_FIX,
            "_error": "PyYAML no instalado · ontology deshabilitada",
        }
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"version": "1.0", "patterns": []}
        # Normalize defaults
        data.setdefault("default_classification", "unclear")
        data.setdefault("default_action", ACTION_AUTO_FIX)
        data.setdefault("patterns", [])
        return data
    except Exception as exc:  # noqa: BLE001
        return {
            "version": "1.0",
            "patterns": [],
            "_error": f"parse error: {exc}",
        }


def _pattern_matches(finding_text: str, finding_rule: str,
                     pattern_entry: dict) -> bool:
    """Check si un pattern del ontology matchea al finding."""
    matches = pattern_entry.get("matches", [])
    if not matches:
        # Si no hay matches · intentar match por rule_id
        rule_ids = pattern_entry.get("rule_ids", [])
        return finding_rule in rule_ids

    for m in matches:
        if not isinstance(m, dict):
            continue
        # Literal match (substring)
        if "literal" in m:
            if m["literal"] in finding_text:
                return True
        # Regex match
        if "regex" in m:
            try:
                flags = 0
                if m.get("flags", "").lower() in ("i", "ignorecase"):
                    flags = re.IGNORECASE
                if re.search(m["regex"], finding_text, flags):
                    return True
            except re.error:
                continue
        # Rule ID match (scoped al rule_id del finding)
        if "rule_id" in m:
            if m["rule_id"] == finding_rule:
                return True
    return False


def classify_finding(
    finding: object,
    ontology: dict,
) -> ClassificationResult:
    """Classifica un finding contra el ontology loaded.

    El `finding` es un objeto con attrs: rule_id, snippet, file, line.
    Usa duck-typing para ser compatible con Finding de security_gate y
    con dicts arbitrarios.

    Flow:
    1. Itera patterns del ontology · primer match gana.
    2. Si no hay match · retorna default_action + default_classification.
    """
    # Extract finding fields (duck-typed)
    rule_id = getattr(finding, "rule_id", "") or (
        finding.get("rule_id", "") if isinstance(finding, dict) else ""
    )
    snippet = getattr(finding, "snippet", "") or (
        finding.get("snippet", "") if isinstance(finding, dict) else ""
    )
    file_path = getattr(finding, "file", "") or (
        finding.get("file", "") if isinstance(finding, dict) else ""
    )
    # Text a buscar · combina snippet + file para max cobertura
    finding_text = f"{snippet}\n{file_path}"

    patterns = ontology.get("patterns", []) or []
    for pattern_entry in patterns:
        if not isinstance(pattern_entry, dict):
            continue
        if _pattern_matches(finding_text, rule_id, pattern_entry):
            # Determine action · v2.1.1 · respeta auto_fix_allowed: false
            # aunque classification sea 'bug' (ej. CWE-287 auth bypass
            # es bug confirmado pero requiere review humano · no auto-fix).
            classification = pattern_entry.get("classification", "unclear")
            auto_fix_allowed = bool(pattern_entry.get("auto_fix_allowed", False))
            if pattern_entry.get("skip", False) or classification == "skip":
                action = ACTION_SKIP
            elif auto_fix_allowed and classification in (
                "bug", "migration_candidate",
            ):
                action = ACTION_AUTO_FIX
            elif classification == "bug" and not auto_fix_allowed:
                # Bug confirmado · pero auto-fix explicitamente deshabilitado ·
                # requiere review humano (ej. auth bypass · no hay fix generico)
                action = ACTION_PAUSE_FOR_REVIEW
            elif classification in ("business_rule", "unclear"):
                action = ACTION_PAUSE_FOR_REVIEW
            else:
                action = ACTION_WARN
            return ClassificationResult(
                action=action,
                ontology_match=pattern_entry.get("id", "<unnamed>"),
                classification=classification,
                message=pattern_entry.get(
                    "pause_message",
                    pattern_entry.get("message", ""),
                ),
                fix_template=pattern_entry.get("fix_template"),
                evidence_required=pattern_entry.get("evidence_required", []) or [],
                tags=pattern_entry.get("tags", []) or [],
            )

    # No match · fall back to defaults
    return ClassificationResult(
        action=ontology.get("default_action", ACTION_AUTO_FIX),
        ontology_match=None,
        classification=ontology.get("default_classification", "unclear"),
        message="No ontology match · default classification",
    )


def summary(findings_with_classification: list[tuple]) -> dict:
    """Genera resumen de classificaciones · util para release_gate.

    Input: lista de (finding, ClassificationResult) tuples.
    Output: dict con counts por action + classification + requires-human list.
    """
    counts_action: dict[str, int] = {}
    counts_class: dict[str, int] = {}
    requires_human: list[dict] = []

    for finding, result in findings_with_classification:
        counts_action[result.action] = counts_action.get(result.action, 0) + 1
        counts_class[result.classification] = (
            counts_class.get(result.classification, 0) + 1
        )
        if result.action == ACTION_PAUSE_FOR_REVIEW:
            requires_human.append({
                "rule_id": getattr(finding, "rule_id", ""),
                "file": getattr(finding, "file", ""),
                "line": getattr(finding, "line", 0),
                "ontology_id": result.ontology_match,
                "classification": result.classification,
                "message": result.message,
            })

    return {
        "total": len(findings_with_classification),
        "by_action": counts_action,
        "by_classification": counts_class,
        "requires_human_review": requires_human,
    }
