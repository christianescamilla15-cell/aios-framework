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


def _paths_match(suppression_file: str, finding_file: str) -> bool:
    """v3.7.5 G-PATH-NORMALIZATION (T8-N1) · match tolerante a scope-reduced paths.

    Caso: `aios-suppressions.json` declara `file: "infra/cdk-pipeline/stacks/x.py"`
    (repo-root path) pero `aios iterate --root infra/cdk-pipeline` emite finding con
    `file: "stacks/x.py"` (relativo a --root) · matcher legacy con `==` falla.

    Match si:
    1. Exact match (caso normal · scope completo)
    2. El path largo termina con `/` + el path corto (separator-aware)

    Ejemplos OK:
    - "infra/cdk-pipeline/stacks/x.py" ↔ "stacks/x.py" → match (long.endswith('/' + short))
    - "x.py" ↔ "x.py" → match (exact)

    Ejemplos NO match (separator-aware previene false positives):
    - "stacks/admin-x.py" vs "x.py" → no match (no separator antes de 'x.py')
    - "other/x.py" vs "stacks/x.py" → no match (paths divergen)
    """
    if suppression_file == finding_file:
        return True
    s = suppression_file.replace("\\", "/")
    f = finding_file.replace("\\", "/")
    if s == f:
        return True
    # Pick the longer · short debe ser sufijo del long con separator
    if len(s) > len(f):
        long_path, short_path = s, f
    else:
        long_path, short_path = f, s
    return long_path.endswith("/" + short_path)


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
        # v3.7.4 G-RULE-ID-UNIFY · si el usuario puso un valor en rule_id que
        # parece una referencia CWE (ej. "CWE-547") y no matchea el rule_id
        # del finding, intentar match contra finding.cwe. Esto permite que
        # una suppression escrita con rule_id="CWE-547" cubra todos los
        # detectores que emiten ese CWE (HARDCODED-INTERNAL-HOSTNAME,
        # STATIC-XYZ, etc.) sin requerir una entry por rule_id concreto.
        if self.rule_id and self.rule_id != finding.rule_id:
            looks_like_cwe = (
                self.rule_id.upper().startswith("CWE-")
                and finding.cwe
                and self.rule_id.upper() == finding.cwe.upper()
            )
            if not looks_like_cwe:
                return False
        # v3.7.4 · si rule_id está vacío pero hay CWE, exigir match exacto
        if not self.rule_id and self.cwe:
            if not finding.cwe or self.cwe.upper() != finding.cwe.upper():
                return False
        # v3.3.2 · file field soporta globs (fnmatch-style): archive/** · *.generated.*
        # v3.7.5 G-PATH-NORMALIZATION (T8-N1) · soporta scope-reduced paths:
        #   suppression "infra/cdk-pipeline/stacks/x.py" matchea finding "stacks/x.py"
        #   cuando `aios iterate --root infra/cdk-pipeline` produce paths relativos a --root.
        if self.file:
            if any(c in self.file for c in "*?["):
                import fnmatch
                file_norm = finding.file.replace("\\", "/")
                pat_norm = self.file.replace("\\", "/")
                if not fnmatch.fnmatch(file_norm, pat_norm):
                    return False
            elif not _paths_match(self.file, finding.file):
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
        # v3.7.4 · acepta `rule` como alias de `rule_id` (UX común en
        # suppressions externas tipo SARIF/Sonar). El alias pierde
        # frente al campo canónico si ambos están presentes.
        rule_id = item.get("rule_id") or item.get("rule") or ""
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
