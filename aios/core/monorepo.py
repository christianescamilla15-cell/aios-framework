"""Monorepo Support — detect and manage multi-service repositories."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, List, Optional


SERVICE_INDICATORS = [
    "package.json", "requirements.txt", "pyproject.toml", "pom.xml",
    "build.gradle", "go.mod", "Cargo.toml", "pubspec.yaml",
]


def detect_services(root: Path) -> List[Dict]:
    """Detect individual services/packages in a monorepo."""
    services = []

    # Check common monorepo patterns
    for pattern_dir in ["services/", "packages/", "apps/", "modules/", "libs/"]:
        parent = root / pattern_dir.rstrip("/")
        if parent.exists():
            for child in parent.iterdir():
                if child.is_dir() and _has_service_indicator(child):
                    services.append({
                        "name": child.name,
                        "path": str(child.relative_to(root)),
                        "type": _detect_service_type(child),
                    })

    # Also check root-level dirs that look like services
    if not services:
        for child in root.iterdir():
            if child.is_dir() and child.name not in {
                ".git", "node_modules", "dist", "build", "__pycache__",
                ".aios", "ai-system", "ai-memory", "specs", "docs", "scripts",
                ".github", ".vscode", "coverage", "infra",
            } and _has_service_indicator(child):
                services.append({
                    "name": child.name,
                    "path": str(child.relative_to(root)),
                    "type": _detect_service_type(child),
                })

    return services


def _has_service_indicator(path: Path) -> bool:
    return any((path / ind).exists() for ind in SERVICE_INDICATORS)


def _detect_service_type(path: Path) -> str:
    if (path / "package.json").exists():
        if any(path.rglob("*.jsx")) or any(path.rglob("*.tsx")):
            return "react"
        return "node"
    if (path / "requirements.txt").exists() or (path / "pyproject.toml").exists():
        return "python"
    if (path / "pom.xml").exists() or (path / "build.gradle").exists():
        return "java"
    if (path / "go.mod").exists():
        return "go"
    if (path / "pubspec.yaml").exists():
        return "flutter"
    return "unknown"


def detect_active_service(root: Path) -> Optional[Dict]:
    """Detect which service the developer is currently working on based on git diff."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD~3"],
            cwd=str(root), capture_output=True, text=True, timeout=5
        )
        changed = result.stdout.strip().split("\n") if result.stdout.strip() else []

        # Count changes per top-level directory
        dir_counts: Dict[str, int] = {}
        for f in changed:
            parts = f.split("/")
            if len(parts) > 1:
                dir_counts[parts[0]] = dir_counts.get(parts[0], 0) + 1

        if not dir_counts:
            return None

        # Most-changed directory is likely the active service
        services = detect_services(root)
        service_names = {s["name"] for s in services}

        most_active = max(dir_counts, key=dir_counts.get)
        if most_active in service_names:
            svc = next(s for s in services if s["name"] == most_active)
            svc["changes"] = dir_counts[most_active]
            return svc

    except Exception:
        pass
    return None


def is_monorepo(root: Path) -> bool:
    """Quick check if this looks like a monorepo."""
    services = detect_services(root)
    return len(services) >= 2
