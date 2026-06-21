"""CI/CD stack checks."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List


def run_checks(root: Path) -> List[Dict]:
    results = []

    # Check 1: CI pipeline exists
    ci_files = list(root.rglob(".github/workflows/*.yml")) + list(root.rglob(".github/workflows/*.yaml"))
    ci_files += list(root.rglob(".gitlab-ci.yml"))
    results.append({"check": "CI pipeline exists", "status": "pass" if ci_files else "warn",
                     "detail": f"{len(ci_files)} pipeline files" if ci_files else "No CI config found"})

    # Check 2: .gitignore exists
    has_gitignore = (root / ".gitignore").exists()
    results.append({"check": ".gitignore exists", "status": "pass" if has_gitignore else "warn"})

    # Check 3: .env pattern protegido por .gitignore
    # v3.5.0 · mensaje clarificado (antes "[XX] .env in .gitignore -- .env
    # may be committed" era ambiguo: el check name sugería "está" pero el
    # status fail significaba "no está"). Ahora el name describe la propiedad
    # deseada y los details son explícitos.
    env_ignored = False
    if has_gitignore:
        content = (root / ".gitignore").read_text(encoding="utf-8", errors="ignore")
        # Busca líneas no-comentadas, no-negativas, que matcheen .env pattern
        for line in content.splitlines():
            s = line.strip()
            if not s or s.startswith("#") or s.startswith("!"):
                continue
            if s == ".env" or s.startswith(".env") or s == "*.env" or s.endswith("/.env"):
                env_ignored = True
                break
    results.append({
        "check": ".env pattern protegido por .gitignore",
        "status": "pass" if env_ignored else "fail",
        "detail": (
            "[OK] .env está listado en .gitignore (secretos no se commitean)"
            if env_ignored else
            "[XX] .env NO aparece en .gitignore · riesgo de commit accidental"
            " de credenciales · agrega '.env' o '.env*' al .gitignore"
        ),
    })

    # Check 4: Dockerfile or docker-compose
    has_docker = (root / "Dockerfile").exists() or (root / "docker-compose.yml").exists()
    results.append({"check": "Docker config exists", "status": "pass" if has_docker else "info",
                     "detail": "Container-ready" if has_docker else "No Docker config"})

    # Check 5: README
    has_readme = (root / "README.md").exists()
    results.append({"check": "README.md exists", "status": "pass" if has_readme else "warn"})

    # v3.5.0 sprint 4 · compliance ACME F01 (badge) + F07 (JIRA traceability)
    # Inspirado en workflow f01-compliance-badge.yml / f07-*.yml de CS_Scripts.
    # Severidad LOW · gobernanza, no bloquea release técnicamente.
    if has_readme:
        readme_text = (root / "README.md").read_text(encoding="utf-8", errors="ignore")
        f01_present = (
            "F01_BADGE_START" in readme_text
            or "F01%20Compliance" in readme_text
            or "F01 Compliance" in readme_text
        )
        results.append({
            "check": "ACME-COMPLIANCE-F01-BADGE",
            "status": "pass" if f01_present else "info",
            "detail": (
                "[OK] Badge F01 presente en README (compliance ACME)"
                if f01_present else
                "[..] Sin badge F01 en README · opcional · agrega workflow "
                "f01-compliance-badge.yml de CS_Scripts si aplica gobernanza"
            ),
        })
        f07_present = (
            "F07_BADGE_START" in readme_text
            or "F07%20JIRA" in readme_text
            or "F07 JIRA" in readme_text
        )
        results.append({
            "check": "ACME-COMPLIANCE-F07-JIRA",
            "status": "pass" if f07_present else "info",
            "detail": (
                "[OK] Badge F07 JIRA Traceability presente"
                if f07_present else
                "[..] Sin badge F07 · opcional · mide trazabilidad de "
                "commits con tickets JIRA [A-Z]+-\\d+"
            ),
        })

    return results
