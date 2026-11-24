"""Docker stack checks."""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List


def run_checks(root: Path) -> List[Dict]:
    results = []

    # Check 1: Dockerfile
    has_dockerfile = (root / "Dockerfile").exists()
    results.append({"check": "Dockerfile exists", "status": "pass" if has_dockerfile else "info"})

    # Check 2: docker-compose
    has_compose = (root / "docker-compose.yml").exists() or (root / "docker-compose.yaml").exists()
    results.append({"check": "docker-compose exists", "status": "pass" if has_compose else "info"})

    # Check 3: .dockerignore
    has_ignore = (root / ".dockerignore").exists()
    results.append({"check": ".dockerignore exists", "status": "pass" if has_ignore else "warn",
                     "detail": "Prevents sending unnecessary files to build context"})

    # Check 4: No :latest in Dockerfile
    if has_dockerfile:
        content = (root / "Dockerfile").read_text(encoding="utf-8", errors="ignore")
        uses_latest = ":latest" in content
        results.append({"check": "No :latest tag in Dockerfile", "status": "warn" if uses_latest else "pass"})

    # Check 5: No secrets in Dockerfile
    if has_dockerfile:
        content = (root / "Dockerfile").read_text(encoding="utf-8", errors="ignore")
        has_secret = any(k in content for k in ["API_KEY", "SECRET", "PASSWORD", "TOKEN"])
        results.append({"check": "No secrets in Dockerfile",
                         "status": "fail" if has_secret else "pass"})

    return results
