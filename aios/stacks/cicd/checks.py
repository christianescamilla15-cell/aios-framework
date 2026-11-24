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

    return results
