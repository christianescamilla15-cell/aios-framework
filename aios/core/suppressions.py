"""Finding suppressions / waivers · file-based tracking.

Archivo `aios-suppressions.json` en el root del proyecto lista findings
que el release gate debe excluir. Cada entry tiene reason + approver +
fecha. Util para manejar:
- False positives confirmados (regex matchea pero codigo es seguro)
- Waivers temporales por stakeholder (ej. "sprint freeze · fix en Q3")
- Hallazgos en codigo legacy que no son riesgo actual

Formato:
[
  {
    "rule_id": "STATIC-SQL-FSTRING",
    "file": "legacy/orm_compat.py",
    "line": 42,
    "cwe": "CWE-89",
    "reason": "Query usa ORM internal API · input sanitized upstream",
    "approver": "Christian Hernandez",
    "approved_at": "2026-04-19",
    "expires_at": "2026-10-01"
  }
]

Matching · una suppression matchea un finding si (rule_id + file +
line) coinciden exactamente. line=0 o omitted actua como wildcard para
toda la file (util para archivos auto-generados).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import date
from pathlib import Path
from typing import Iterable, Optional

from .security_gate import Finding


_SUPPRESSIONS_FILE = "aios-suppressions.json"


@dataclass
class Suppression:
    rule_id: str
    file: str
    line: int = 0  # 0 = wildcard toda la file
    cwe: str = ""
    reason: str = ""
    approver: str = ""
    approved_at: str = ""
    expires_at: str = ""  # ISO date · vacio = no expira

    def matches(self, finding: Finding) -> bool:
        if self.rule_id and self.rule_id != finding.rule_id:
            return False
        # v3.3.2 · file field soporta globs (fnmatch-style): archive/** · *.generated.*
        if self.file:
            if any(c in self.file for c in "*?["):
                import fnmatch
                file_norm = finding.file.replace("\\", "/")
                pat_norm = self.file.replace("\\", "/")
                if not fnmatch.fnmatch(file_norm, pat_norm):
                    return False
            elif self.file != finding.file:
                return False
        if self.line > 0 and self.line != finding.line:
            return False
        return True

    def is_expired(self, today: Optional[date] = None) -> bool:
        if not self.expires_at:
            return False
        try:
            exp = date.fromisoformat(self.expires_at)
        except ValueError:
            return False
        return (today or date.today()) > exp


def load_suppressions(root: Path) -> list[Suppression]:
    """Lee `aios-suppressions.json` del root · retorna lista vacia si
    no existe o es invalido.

    v3.3.2 · acepta tambien {"suppressions": [...]} como wrapper y
    entries con `pattern` (path glob) que se convierten a file-based
    suppression con rule_id wildcard. Warning opcional si entry tiene
    pattern pero no esta claro el intent.
    """
    sup_file = root / _SUPPRESSIONS_FILE
    if not sup_file.exists():
        return []
    try:
        data = json.loads(sup_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    # v3.3.2 · acepta tanto lista top-level como {"suppressions": [...]}
    if isinstance(data, dict):
        data = data.get("suppressions", [])
    if not isinstance(data, list):
        return []
    out: list[Suppression] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        # v3.3.2 · entry con `pattern` = path glob sin rule_id · se trata
        # como wildcard rule_id + file=pattern · aplica a todos los findings
        # cuyo path matchea el pattern (ej. "archive/**")
        pattern = item.get("pattern", "")
        rule_id = item.get("rule_id", "")
        file_field = item.get("file", "")
        if pattern and not rule_id and not file_field:
            file_field = pattern  # glob path exclusion
        try:
            out.append(Suppression(
                rule_id=rule_id,  # vacio = matchea cualquier rule
                file=file_field,
                line=int(item.get("line", 0)),
                cwe=item.get("cwe", ""),
                reason=item.get("reason", ""),
                approver=item.get("approver", ""),
                approved_at=item.get("approved_at", ""),
                expires_at=item.get("expires_at", ""),
            ))
        except (TypeError, ValueError):
            continue
    return out


def apply_suppressions(
    findings: Iterable[Finding],
    suppressions: list[Suppression],
    today: Optional[date] = None,
) -> tuple[list[Finding], list[tuple[Finding, Suppression]]]:
    """Separa findings activos de findings suprimidos por un waiver
    no expirado. Waivers expirados son ignorados (el finding no se
    suprime y se debe revisar).

    Returns · (active_findings, suppressed [con referencia al waiver])
    """
    active: list[Finding] = []
    suppressed: list[tuple[Finding, Suppression]] = []
    for f in findings:
        matched = None
        for s in suppressions:
            if s.is_expired(today):
                continue
            if s.matches(f):
                matched = s
                break
        if matched:
            suppressed.append((f, matched))
        else:
            active.append(f)
    return active, suppressed


def add_suppression(root: Path, suppression: Suppression) -> Path:
    """Persiste nueva suppression al file · crea archivo si no existe."""
    sup_file = root / _SUPPRESSIONS_FILE
    existing: list[dict] = []
    if sup_file.exists():
        try:
            raw = json.loads(sup_file.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                existing = raw
        except (json.JSONDecodeError, OSError):
            pass
    existing.append(asdict(suppression))
    sup_file.write_text(
        json.dumps(existing, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return sup_file


def list_expired(suppressions: list[Suppression], today: Optional[date] = None) -> list[Suppression]:
    return [s for s in suppressions if s.is_expired(today)]
