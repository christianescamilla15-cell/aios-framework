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

    # Check 3: .env in .gitignore
    env_ignored = False
    if has_gitignore:
        content = (root / ".gitignore").read_text(encoding="utf-8", errors="ignore")
        env_ignored = ".env" in content
    results.append({"check": ".env in .gitignore", "status": "pass" if env_ignored else "fail",
                     "detail": "Secrets protected" if env_ignored else ".env may be committed"})

    # Check 4: Dockerfile or docker-compose
    has_docker = (root / "Dockerfile").exists() or (root / "docker-compose.yml").exists()
    results.append({"check": "Docker config exists", "status": "pass" if has_docker else "info",
                     "detail": "Container-ready" if has_docker else "No Docker config"})

    # Check 5: README
    has_readme = (root / "README.md").exists()
    results.append({"check": "README.md exists", "status": "pass" if has_readme else "warn"})

    return results
