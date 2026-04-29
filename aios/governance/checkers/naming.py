"""NamingChecker · valida 5 patterns AMX (IAM · Repo · CMK · Secret · Branch).

Recorre archivos del proyecto buscando ocurrencias y verifica regex pattern.
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
    """
    # Convertir globs a sufijos para matching rápido
    suffixes: set[str] = set()
    has_root_match = False
    for pattern in globs:
        if "/" in pattern and "**" not in pattern:
            # Pattern específico de root level (.git/config · package.json)
            has_root_match = True
        elif pattern.startswith("**/*"):
            ext = pattern[len("**/*"):]
            suffixes.add(ext)

    # Root-level matches (sin walk)
    seen: set[Path] = set()
    count = 0
    if has_root_match:
        for pattern in globs:
            if "/" in pattern and "**" not in pattern:
                for path in root.glob(pattern):
                    if path.is_file() and path not in seen:
                        seen.add(path)
                        yield path
                        count += 1
                        if count >= MAX_FILES_PER_KIND:
                            return

    # Walk con poda de directorios
    for dirpath, dirnames, filenames in os.walk(root):
        # Mutar dirnames in-place poda el descenso (clave para velocidad)
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]

        for fname in filenames:
            ext = os.path.splitext(fname)[1]
            if ext in suffixes:
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
    """Valida los 5 detectores de naming AMX (G-NEW-IAM-NAMING-FULL · etc.)."""

    def __init__(self, rules: GovernanceRules):
        self._rules = rules

    def check(self, root: Path, app: str) -> list[GovernanceFinding]:
        """Ejecuta los 5 detectores · retorna findings."""
        findings: list[GovernanceFinding] = []
        findings.extend(self._check_iam_naming(root, app))
        findings.extend(self._check_cmk_naming(root, app))
        findings.extend(self._check_secret_naming(root, app))
        findings.extend(self._check_kms_aws_managed_prohibition(root))
        return findings

    # -----------------------------------------------------------------------
    # 1 · IAM Role naming
    # -----------------------------------------------------------------------

    def _check_iam_naming(self, root: Path, app: str) -> list[GovernanceFinding]:
        rule = self._rules.get_naming_pattern("iam_role_naming")
        pattern = re.compile(rule["pattern_regex"])
        # Match cualquier string que parezca un IAM role name (AMX-* o AMX_*)
        candidate = re.compile(r"\bAMX[-_][A-Z][A-Z0-9_-]{2,40}\b")

        findings: list[GovernanceFinding] = []
        for path in _iter_files(root, FILE_GLOBS["iam_role"]):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for match in candidate.finditer(text):
                token = match.group(0)
                # Solo flagueamos si parece intento de IAM role · evitamos prefijos genéricos
                if not token.startswith("AMX-R-"):
                    continue
                if not pattern.match(token):
                    line = text[: match.start()].count("\n") + 1
                    findings.append(GovernanceFinding(
                        rule_id="G-NEW-IAM-NAMING-FULL",
                        severity=CheckSeverity.FAIL,
                        category="naming",
                        message=(
                            f"IAM role '{token}' NO sigue convención "
                            f"AMX-R-{{App}}-{{A|DES|SL}}"
                        ),
                        location=f"{path.relative_to(root)}:{line}",
                        suggestion=f"Renombrar a AMX-R-{app.upper()}-DES (o -A · -SL según corresponda)",
                    ))
        return findings

    # -----------------------------------------------------------------------
    # 2 · CMK alias naming
    # -----------------------------------------------------------------------

    def _check_cmk_naming(self, root: Path, app: str) -> list[GovernanceFinding]:
        rule = self._rules.get_naming_pattern("cmk_naming")
        pattern = re.compile(rule["pattern_regex"])
        candidate = re.compile(r"['\"]?(alias/[a-zA-Z0-9_/-]{3,80})['\"]?")

        findings: list[GovernanceFinding] = []
        for path in _iter_files(root, FILE_GLOBS["cmk"]):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for match in candidate.finditer(text):
                full_alias = match.group(1)  # ej. "alias/amx-kms-sicofav-secrets"
                short = full_alias.removeprefix("alias/")
                # Solo aliases que parezcan custom AMX
                if not short.startswith("amx-kms-"):
                    continue
                if not pattern.match(short):
                    line = text[: match.start()].count("\n") + 1
                    findings.append(GovernanceFinding(
                        rule_id="G-NEW-CMK-NAMING",
                        severity=CheckSeverity.WARN,
                        category="naming",
                        message=f"CMK alias '{full_alias}' NO sigue convención amx-kms-{{app}}-{{scope}}",
                        location=f"{path.relative_to(root)}:{line}",
                        suggestion=f"Usar amx-kms-{app}-secrets (o -aurora · -s3-cfdis · -logs · -ebs)",
                    ))
        return findings

    # -----------------------------------------------------------------------
    # 3 · Secrets Manager naming
    # -----------------------------------------------------------------------

    def _check_secret_naming(self, root: Path, app: str) -> list[GovernanceFinding]:
        rule = self._rules.get_naming_pattern("secret_naming")
        pattern = re.compile(rule["pattern_regex"])
        candidate = re.compile(r"['\"](amx/[a-zA-Z0-9_/-]+)['\"]")

        findings: list[GovernanceFinding] = []
        for path in _iter_files(root, FILE_GLOBS["secret"]):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for match in candidate.finditer(text):
                secret_name = match.group(1)
                if not pattern.match(secret_name):
                    line = text[: match.start()].count("\n") + 1
                    findings.append(GovernanceFinding(
                        rule_id="G-NEW-SECRET-NAMING",
                        severity=CheckSeverity.WARN,
                        category="naming",
                        message=f"Secret name '{secret_name}' NO sigue amx/{{##-app}}/{{type}}",
                        location=f"{path.relative_to(root)}:{line}",
                        suggestion="Ej: amx/01-sicofav/db · amx/10-noshow/sabre-sandbox",
                    ))
        return findings

    # -----------------------------------------------------------------------
    # 4 · AWS-managed KMS prohibition (CRITICAL)
    # -----------------------------------------------------------------------

    def _check_kms_aws_managed_prohibition(self, root: Path) -> list[GovernanceFinding]:
        forbidden = re.compile(r"['\"]alias/aws/[a-z0-9_-]+['\"]")
        findings: list[GovernanceFinding] = []
        for path in _iter_files(root, FILE_GLOBS["cmk"]):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for match in forbidden.finditer(text):
                line = text[: match.start()].count("\n") + 1
                findings.append(GovernanceFinding(
                    rule_id="G-CDK-KMS-AWS-MANAGED-PROHIBITION",
                    severity=CheckSeverity.CRITICAL,
                    category="naming",
                    message=(
                        f"AWS-managed key prohibida: {match.group(0)} · "
                        "regla AMX kms-aws-managed-keys-prohibition"
                    ),
                    location=f"{path.relative_to(root)}:{line}",
                    suggestion="Usar CMK customer-managed (alias/amx-kms-{app}-{scope})",
                ))
        return findings
