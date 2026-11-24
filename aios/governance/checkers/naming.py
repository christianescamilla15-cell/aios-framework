"""NamingChecker · valida las convenciones de nombres de rules/naming.yaml (IAM · CMK · secretos).

Recorre archivos del proyecto buscando candidatos y verifica cada uno contra el regex del YAML. Los
prefijos (`acme-role-`, `acme-kms-`, `acme/`) son los de la organización ficticia de ejemplo.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterator

from ..loader import GovernanceRules
from ..models import CheckSeverity, GovernanceFinding


# ---------------------------------------------------------------------------
# Patrones de archivos a inspeccionar por tipo de naming
# ---------------------------------------------------------------------------

FILE_GLOBS = {
    "iam_role": ["**/*.py", "**/*.ts", "**/*.tf", "**/cdk*.json", "**/*.yaml", "**/*.yml"],
    "repo": [".git/config", "package.json", ".github/workflows/*.yml", ".github/workflows/*.yaml"],
    "cmk": ["**/cdk*.py", "**/*.ts", "**/*.tf", "**/*.yaml", "**/*.yml"],
    "secret": ["**/*.py", "**/*.cs", "**/*.ts", "**/*.tf", "**/*.yaml", "**/*.yml"],
}

EXCLUDED_DIRS = {
    "node_modules", ".venv", "venv", "env", "__pycache__",
    "bin", "obj", ".aios", "cdk.out", ".git",
    "TestResults", "build", "dist", ".vs", ".idea",
    "packages", "wwwroot", "_legacy",
}
MAX_FILES_PER_KIND = 500  # límite para evitar lentitud en repos grandes


# ---------------------------------------------------------------------------
# Helper · iterar archivos respetando excludes (rápido · poda al descender)
# ---------------------------------------------------------------------------

def _iter_files(root: Path, globs: list[str]) -> Iterator[Path]:
    """Iterator perezoso usando os.walk con poda de directorios.

    A diferencia de Path.glob('**/*.py') · este SÍ poda EXCLUDED_DIRS antes
    de descender · evitando recorrer .venv/cdk.out/node_modules en repos grandes.

    Soporta tres formas de patterns:
      - **/*.ext           → matching por sufijo (rápido)
      - **/<filename_glob> → fnmatch del filename (ej: cdk*.py · iam*.ts)
      - dir/file.ext       → root-level glob (.git/config · package.json)
    """
    import fnmatch

    # Clasificar patterns en 3 categorías
    suffixes: set[str] = set()           # **/*.ext
    fname_patterns: list[str] = []        # **/<glob> (con prefijo o glob)
    root_patterns: list[str] = []         # dir/file (sin **/)

    for pattern in globs:
        if pattern.startswith("**/*."):
            # Caso clásico **/*.py · solo sufijo
            suffixes.add(pattern[len("**/*"):])
        elif pattern.startswith("**/"):
            # Caso prefix glob **/cdk*.py · usar fnmatch sobre filename
            fname_patterns.append(pattern[len("**/"):])
        elif "/" in pattern and "**" not in pattern:
            root_patterns.append(pattern)
        else:
            # Fallback · trate como filename glob plano
            fname_patterns.append(pattern)

    seen: set[Path] = set()
    count = 0

    # 1 · Root-level matches (sin walk · paths absolutos relativos a root)
    for pattern in root_patterns:
        for path in root.glob(pattern):
            if path.is_file() and path not in seen:
                seen.add(path)
                yield path
                count += 1
                if count >= MAX_FILES_PER_KIND:
                    return

    # 2 · Walk recursivo con poda + filtros
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]

        for fname in filenames:
            matched = False
            ext = os.path.splitext(fname)[1]
            if ext in suffixes:
                matched = True
            elif fname_patterns and any(fnmatch.fnmatch(fname, p) for p in fname_patterns):
                matched = True

            if matched:
                path = Path(dirpath) / fname
                if path in seen:
                    continue
                seen.add(path)
                yield path
                count += 1
                if count >= MAX_FILES_PER_KIND:
                    return


# ---------------------------------------------------------------------------
# Checker principal
# ---------------------------------------------------------------------------

class NamingChecker:
    """Valida los detectores de naming de rules/naming.yaml (rol IAM · llave KMS · secreto · KMS de AWS)."""

    def __init__(self, rules: GovernanceRules):
        self._rules = rules

    def check(self, root: Path, app: str) -> list[GovernanceFinding]:
        """Ejecuta los 4 detectores · retorna findings."""
        findings: list[GovernanceFinding] = []
        findings.extend(self._check_iam_naming(root, app))
        findings.extend(self._check_cmk_naming(root, app))
        findings.extend(self._check_secret_naming(root, app))
        findings.extend(self._check_kms_aws_managed_prohibition(root))
        return findings

    @staticmethod
    def _line_of(text: str, pos: int) -> int:
        return text[:pos].count("\n") + 1

    def _texts(self, root: Path, kind: str) -> Iterator[tuple[Path, str]]:
        for path in _iter_files(root, FILE_GLOBS[kind]):
            try:
                yield path, path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

    # -----------------------------------------------------------------------
    # 1 · Rol IAM
    # -----------------------------------------------------------------------

    def _check_iam_naming(self, root: Path, app: str) -> list[GovernanceFinding]:
        rule = self._rules.get_naming_pattern("iam_role_naming")
        rule_id = rule.get("detector_id", "G-IAM-ROLE-NAMING")
        pattern = re.compile(rule["pattern_regex"])
        # Candidato: cualquier token que empiece con el prefijo de roles (sin distinguir mayúsculas)
        candidate = re.compile(r"\bacme-role-[A-Za-z0-9_-]{1,60}", re.IGNORECASE)
        reserved_prefixes = tuple(
            r["prefix"] for r in rule.get("reserved_prefixes", [])
            if isinstance(r, dict) and "prefix" in r
        )

        findings: list[GovernanceFinding] = []
        for path, text in self._texts(root, "iam_role"):
            for match in candidate.finditer(text):
                token = match.group(0)
                if reserved_prefixes and token.startswith(reserved_prefixes):
                    continue
                if not pattern.match(token):
                    findings.append(GovernanceFinding(
                        rule_id=rule_id,
                        severity=CheckSeverity.FAIL,
                        category="naming",
                        message=f"Rol IAM '{token}' NO sigue acme-role-{{app}}-{{admin|dev|readonly}}",
                        location=f"{path.relative_to(root)}:{self._line_of(text, match.start())}",
                        suggestion=f"Renombrar a acme-role-{app}-dev (o -admin · -readonly según corresponda)",
                    ))
        return findings

    # -----------------------------------------------------------------------
    # 2 · Alias de llave KMS
    # -----------------------------------------------------------------------

    def _check_cmk_naming(self, root: Path, app: str) -> list[GovernanceFinding]:
        rule = self._rules.get_naming_pattern("cmk_naming")
        rule_id = rule.get("detector_id", "G-CMK-NAMING")
        pattern = re.compile(rule["pattern_regex"])
        candidate = re.compile(r"['\"]?(alias/[a-zA-Z0-9_/-]{3,80})['\"]?")
        scopes = " · ".join(rule.get("required_5_per_dedicated_account", []))

        findings: list[GovernanceFinding] = []
        for path, text in self._texts(root, "cmk"):
            for match in candidate.finditer(text):
                full_alias = match.group(1)
                short = full_alias.removeprefix("alias/")
                if not short.lower().startswith("acme-kms-"):
                    continue  # sólo alias propios de la organización
                if not pattern.match(short):
                    findings.append(GovernanceFinding(
                        rule_id=rule_id,
                        severity=CheckSeverity.WARN,
                        category="naming",
                        message=f"Alias '{full_alias}' NO sigue acme-kms-{{app}}-{{alcance}}",
                        location=f"{path.relative_to(root)}:{self._line_of(text, match.start())}",
                        suggestion=f"Usar acme-kms-{app}-<alcance> con alcance ∈ {scopes}",
                    ))
        return findings

    # -----------------------------------------------------------------------
    # 3 · Secretos
    # -----------------------------------------------------------------------

    def _check_secret_naming(self, root: Path, app: str) -> list[GovernanceFinding]:
        rule = self._rules.get_naming_pattern("secret_naming")
        rule_id = rule.get("detector_id", "G-SECRET-NAMING")
        pattern = re.compile(rule["pattern_regex"])
        candidate = re.compile(r"['\"](acme/[a-zA-Z0-9_/-]+)['\"]")

        findings: list[GovernanceFinding] = []
        for path, text in self._texts(root, "secret"):
            for match in candidate.finditer(text):
                secret_name = match.group(1)
                if not pattern.match(secret_name):
                    findings.append(GovernanceFinding(
                        rule_id=rule_id,
                        severity=CheckSeverity.WARN,
                        category="naming",
                        message=f"Secreto '{secret_name}' NO sigue acme/{{app}}/{{nombre}}",
                        location=f"{path.relative_to(root)}:{self._line_of(text, match.start())}",
                        suggestion=f"Ej: acme/{app}/db · acme/{app}/api-token",
                    ))
        return findings

    # -----------------------------------------------------------------------
    # 4 · Llaves administradas por AWS (CRITICAL)
    # -----------------------------------------------------------------------

    def _check_kms_aws_managed_prohibition(self, root: Path) -> list[GovernanceFinding]:
        rule = self._rules.get_naming_pattern("cmk_naming").get("prohibited_aws_managed", {})
        rule_id = rule.get("detector_id", "G-KMS-AWS-MANAGED-PROHIBITED")
        forbidden = re.compile(r"['\"]alias/aws/[a-z0-9_-]+['\"]")
        findings: list[GovernanceFinding] = []
        for path, text in self._texts(root, "cmk"):
            for match in forbidden.finditer(text):
                findings.append(GovernanceFinding(
                    rule_id=rule_id,
                    severity=CheckSeverity.CRITICAL,
                    category="naming",
                    message=(
                        f"Llave administrada por AWS prohibida: {match.group(0)} · "
                        "no admite política ni rotación propias"
                    ),
                    location=f"{path.relative_to(root)}:{self._line_of(text, match.start())}",
                    suggestion="Usar una llave administrada por el cliente (alias/acme-kms-{app}-{alcance})",
                ))
        return findings
