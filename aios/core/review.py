"""Stakeholder-in-the-Loop · v2.1.0 · RFC-003 Nivel 4

Convierte el `pause_for_review` del Nivel 1/2 en decisiones accionables
con audit trail persistente. Genera review docs automáticos con todo el
contexto (ontology · LLM · characterization · git blame · surrounding).

Flow canónico:
  1. release_gate detecta N findings pause_for_review
  2. aios review · genera .aios/reviews/*.md con contexto + recomendación
  3. Usuario (o Kiro en modo interactivo) decide:
     - approve · finding aceptado · NO se refactoriza (business_rule
       confirmado) o SÍ (si decide override a bug)
     - reject · rollback trigger · finding bloquea release
     - defer · pospuesto con razón · queda pending
     - add-to-ontology · approve + propone YAML snippet para que el
       catálogo canónico AMX cubra este pattern en futuros scans
  4. .aios/review-log.jsonl · audit trail inmutable (append-only)
  5. Próximos scans leen el log · skip approved · block rejected

Estructura:
  .aios/reviews/
    FRK-<hash8>.md           · review doc markdown
  .aios/review-log.jsonl     · append-only JSON log
  .aios/ontology-proposed.yaml · patterns propuestos (user merge manual)

Cada entry del log:
  {
    "timestamp": "2026-04-22T22:30:45Z",
    "finding_id": "FRK-a3f8e1b2",
    "file": "NoShowService.cs", "line": 47,
    "rule_id": "FORBIDDEN-LITERAL-829",
    "action": "approve|reject|defer",
    "reason": "string",
    "user": "christian.hernandez",
    "ontology_proposed": bool,
    "pre_decision": { "ontology_action", "llm_classification", ... }
  }

Diseño intencional:
- Log append-only · nunca mutamos entries previas (audit integrity)
- finding_id deterministico (hash de file:line:rule_id) · re-scans
  mantienen el mismo ID
- JSON lines format · streamable · CI/CD friendly
- Ontology proposed se genera aparte · usuario hace merge manual
  (evitar mutaciones automáticas de archivos de policy)

Deriva de RFC-003 Nivel 4 · BACKLOG · feedback LM-FRK70K 2026-04-22.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


VALID_ACTIONS = ("approve", "reject", "defer")
VALID_APPROVE_CLASSES = ("bug", "business_rule", "migration_candidate", "unclear")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass
class ReviewDecision:
    """Una decisión registrada sobre un finding."""
    timestamp: str
    finding_id: str
    file: str
    line: int
    rule_id: str
    action: str  # approve · reject · defer
    reason: str = ""
    user: str = ""
    # Al aprobar · reclasificar (sobrescribe la clase del Nivel 1/2)
    final_classification: str = ""  # bug · business_rule · migration_candidate
    # Si true · el usuario propuso agregar a ontology
    ontology_proposed: bool = False
    # Snapshot del estado pre-decision (para auditoría)
    pre_decision: dict = field(default_factory=dict)


def make_finding_id(file: str, line: int, rule_id: str) -> str:
    """ID determinístico · re-scans retornan el mismo hash."""
    material = f"{file}:{line}:{rule_id}".encode("utf-8")
    return "FRK-" + hashlib.sha1(material).hexdigest()[:10]


# ---------------------------------------------------------------------------
# Review doc generation
# ---------------------------------------------------------------------------

def generate_review_doc(finding: dict, root: Path) -> Path:
    """Genera un markdown review doc para un finding.

    El finding es un dict con los campos que run_security_gate emite en
    requires_human_review (incluye nivel 1 ontology + nivel 2 llm).
    """
    finding_id = finding.get(
        "finding_id",
        make_finding_id(
            finding.get("file", ""),
            int(finding.get("line", 0) or 0),
            finding.get("rule_id", ""),
        ),
    )
    reviews_dir = root / ".aios" / "reviews"
    reviews_dir.mkdir(parents=True, exist_ok=True)
    out = reviews_dir / f"{finding_id}.md"

    sev = finding.get("severity", "UNKNOWN")
    ontology = {
        "match": finding.get("ontology_match") or finding.get("match"),
        "classification": finding.get("classification", "unclear"),
        "message": finding.get("message", ""),
    }
    llm = finding.get("llm") or {}

    md = [
        f"# Review · {finding_id}",
        "",
        f"**File:** `{finding.get('file','')}`  ",
        f"**Line:** {finding.get('line','?')}  ",
        f"**Rule:** `{finding.get('rule_id','')}`  ",
        f"**Severity:** {sev}  ",
        f"**Generated:** {datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}",
        "",
        "## Nivel 1 · Ontology classification",
        "",
        f"- **Match:** `{ontology['match']}`" if ontology['match']
            else "- **Match:** (ninguno · default clasificación)",
        f"- **Classification:** {ontology['classification']}",
        f"- **Message:** {ontology['message']}" if ontology['message'] else "",
        "",
    ]
    if llm:
        md += [
            "## Nivel 2 · LLM analysis",
            "",
            f"- **Provider:** {llm.get('provider','?')} (cached={llm.get('cached', False)})",
            f"- **Classification:** {llm.get('classification','?')}",
            f"- **Confidence:** {llm.get('confidence', 0):.2f}",
            "",
            f"### Reasoning",
            "",
            f"{llm.get('reasoning', '(no reasoning)')}",
            "",
        ]
        evidence = llm.get("evidence") or []
        if evidence:
            md += ["### Evidence", ""]
            md += [f"- {e}" for e in evidence]
            md += [""]
    md += [
        "## Decisión requerida",
        "",
        "Elige UNA:",
        "",
        "- **approve** · finding aceptado (o re-clasificado). Justificar en razón.",
        "- **reject** · el refactor propuesto rompe dominio · rollback required.",
        "- **defer** · pospuesto con razón · seguirá apareciendo en próximos scans.",
        "",
        "### CLI",
        "",
        "```bash",
        f"aios review approve --id {finding_id} "
        f"--reason \"es regla de negocio · ver ADR-XXX\" "
        f"--classification business_rule",
        "",
        f"aios review reject --id {finding_id} "
        f"--reason \"refactor propuesto cambia signature publica\"",
        "",
        f"aios review defer --id {finding_id} "
        f"--reason \"esperar decision de Miguel Rachid\"",
        "```",
        "",
        "### Proponer al ontology (opcional · accelera futuros scans)",
        "",
        "Si al approve este finding identificas un pattern reusable,",
        "agrega `--add-to-ontology --pattern \"regex\"` · el framework",
        "genera un snippet YAML en `.aios/ontology-proposed.yaml` para",
        "que lo mergees al catálogo canónico (aprobación equipo AMX).",
    ]
    out.write_text("\n".join(md) + "\n", encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Persistence · log + queries
# ---------------------------------------------------------------------------

def _log_path(root: Path) -> Path:
    return root / ".aios" / "review-log.jsonl"


def log_decision(root: Path, decision: ReviewDecision) -> None:
    """Append-only log · audit integrity."""
    log_file = _log_path(root)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": decision.timestamp,
        "finding_id": decision.finding_id,
        "file": decision.file,
        "line": decision.line,
        "rule_id": decision.rule_id,
        "action": decision.action,
        "reason": decision.reason,
        "user": decision.user,
        "final_classification": decision.final_classification,
        "ontology_proposed": decision.ontology_proposed,
        "pre_decision": decision.pre_decision,
    }
    with log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_decisions(root: Path) -> list[ReviewDecision]:
    """Lee todas las decisiones del log · en orden cronológico."""
    log_file = _log_path(root)
    if not log_file.exists():
        return []
    decisions: list[ReviewDecision] = []
    for line in log_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            decisions.append(ReviewDecision(
                timestamp=data.get("timestamp", ""),
                finding_id=data.get("finding_id", ""),
                file=data.get("file", ""),
                line=int(data.get("line", 0) or 0),
                rule_id=data.get("rule_id", ""),
                action=data.get("action", ""),
                reason=data.get("reason", ""),
                user=data.get("user", ""),
                final_classification=data.get("final_classification", ""),
                ontology_proposed=bool(data.get("ontology_proposed", False)),
                pre_decision=data.get("pre_decision") or {},
            ))
        except (json.JSONDecodeError, ValueError, TypeError):
            continue
    return decisions


def latest_decision(root: Path, finding_id: str) -> Optional[ReviewDecision]:
    """Retorna la última decision para un finding · None si no hay."""
    matches = [d for d in read_decisions(root) if d.finding_id == finding_id]
    return matches[-1] if matches else None


def effective_decisions(root: Path) -> dict[str, ReviewDecision]:
    """Retorna dict {finding_id: última decision} · útil para apply."""
    out: dict[str, ReviewDecision] = {}
    for d in read_decisions(root):
        out[d.finding_id] = d  # overwrite con última cronológicamente
    return out


# ---------------------------------------------------------------------------
# Ontology proposal (snippet para merge manual · no auto-mutate)
# ---------------------------------------------------------------------------

def propose_ontology_entry(
    root: Path, finding_id: str, rule_id: str, snippet: str,
    classification: str, reason: str,
    pattern_override: str = "",
) -> Path:
    """Genera snippet YAML al `.aios/ontology-proposed.yaml` para
    que user haga merge manual al catálogo canónico. Append-only.
    """
    out_file = root / ".aios" / "ontology-proposed.yaml"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    # Build YAML entry manual (sin depender de PyYAML para escribir)
    auto_fix = "true" if classification in ("bug", "migration_candidate") else "false"
    pattern = pattern_override or _extract_distinctive_pattern(snippet)
    entry = [
        "",
        f"# Propuesto desde review de {finding_id} · {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        f"# Razón: {reason}",
        f"- id: {_generate_ontology_id(rule_id, snippet)}",
        f"  description: \"{reason[:80]}\"",
        "  matches:",
        f"    - regex: '{pattern}'",
        f"  classification: \"{classification}\"",
        f"  auto_fix_allowed: {auto_fix}",
        "  tags: [\"proposed\", \"review\"]",
    ]
    existing = out_file.read_text(encoding="utf-8") if out_file.exists() else ""
    if not existing:
        existing = (
            "# Ontology patterns propuestos durante reviews\n"
            "# MERGE MANUAL al catálogo canónico "
            "(aios/policies/<policy>/ontology.yaml) tras aprobación AMX.\n"
        )
    out_file.write_text(existing + "\n".join(entry) + "\n", encoding="utf-8")
    return out_file


def _extract_distinctive_pattern(snippet: str) -> str:
    """Extrae pattern regex distintivo del snippet."""
    import re as _re
    if not snippet:
        return ""
    m = _re.search(r'"([^"]{3,80})"', snippet)
    if m:
        # Escape regex metacharacters
        return _re.escape(m.group(1))
    m = _re.search(r"'([^']{3,80})'", snippet)
    if m:
        return _re.escape(m.group(1))
    words = _re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", snippet)
    if words:
        words.sort(key=len, reverse=True)
        return _re.escape(words[0])
    return ""


def _generate_ontology_id(rule_id: str, snippet: str) -> str:
    """Genera un id YAML-friendly uppercase."""
    import re as _re
    token = ""
    m = _re.search(r'"([^"]{3,30})"', snippet or "")
    if m:
        token = m.group(1)
    elif snippet:
        words = _re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", snippet)
        token = words[0] if words else rule_id
    else:
        token = rule_id
    token = _re.sub(r"[^A-Za-z0-9_]", "_", token).upper()[:30]
    return f"{token}_PROPOSED"


# ---------------------------------------------------------------------------
# Apply decisions (consumed by security_gate / release_gate)
# ---------------------------------------------------------------------------

def filter_findings_by_decisions(
    findings_pause: list[dict], root: Path,
) -> dict:
    """Filtra findings pause_for_review aplicando decisiones previas.

    Retorna:
      {
        "pending": list[dict]   · sin decision · siguen como pause
        "approved": list[dict]  · aprobados · se retiran del pause
        "rejected": list[dict]  · rechazados · bloquean release
        "deferred": list[dict]  · pospuestos · siguen como pause
      }
    """
    decisions = effective_decisions(root)
    buckets: dict[str, list[dict]] = {
        "pending": [], "approved": [], "rejected": [], "deferred": [],
    }
    for f in findings_pause:
        fid = f.get("finding_id") or make_finding_id(
            f.get("file", ""), int(f.get("line", 0) or 0), f.get("rule_id", ""),
        )
        f_with_id = dict(f)
        f_with_id["finding_id"] = fid
        decision = decisions.get(fid)
        if decision is None:
            buckets["pending"].append(f_with_id)
            continue
        if decision.action == "approve":
            buckets["approved"].append(f_with_id)
        elif decision.action == "reject":
            buckets["rejected"].append(f_with_id)
        elif decision.action == "defer":
            buckets["deferred"].append(f_with_id)
        else:
            buckets["pending"].append(f_with_id)
    return buckets
