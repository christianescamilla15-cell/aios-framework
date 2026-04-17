"""Repo Analyzer — scans repository to detect stack, modules, hotspots."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, List

from .file_scanner import scan_tracked_files


def detect_stack(files: List[str]) -> List[str]:
    stack = set()
    indicators = {
        "python": ["requirements.txt", "pyproject.toml", "setup.py", ".py"],
        "node": ["package.json", "yarn.lock"],
        "react": ["App.jsx", "App.tsx", "vite.config.js"],
        "java": ["pom.xml", "build.gradle", ".java"],
        "kotlin": [".kt", "build.gradle.kts"],
        "flutter": ["pubspec.yaml", ".dart"],
        "docker": ["Dockerfile", "docker-compose.yml"],
        "terraform": [".tf"],
        "kubernetes": ["kustomization.yaml"],
        "postgres": ["migrations/", "asyncpg"],
        "fastapi": ["fastapi", "uvicorn"],
        "aws": [".tf", "bedrock", "lambda"],
    }
    files_lower = " ".join(f.lower() for f in files)
    for tech, patterns in indicators.items():
        if any(p in files_lower for p in patterns):
            stack.add(tech)
    return sorted(stack)


def map_modules(files: List[str]) -> Dict[str, int]:
    modules = defaultdict(int)
    for f in files:
        parts = f.replace("\\", "/").split("/")
        if len(parts) > 1 and not parts[0].startswith("."):
            modules[parts[0]] += 1
    return dict(sorted(modules.items(), key=lambda x: -x[1])[:20])


def detect_hotspots(root: Path, files: List[str]) -> List[Dict]:
    """v1.5.0 · expanded extensions (.cs · .vb · .php · .cbl) + ignore noise paths.

    Excludes: gen_*.py, analysis_output/, _archive/, bin/obj, node_modules, etc.
    """
    hotspots = []
    code_exts = {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go",
        ".cs", ".vb",  # v1.5.0 · .NET
        ".php",
        ".cbl", ".cob", ".cobol", ".cpy",  # COBOL
    }
    noise_substrings = (
        "gen_", "analysis_output/", "noshow_analysis/", "_archive/",
        "__pycache__/", "node_modules/", "/bin/", "/obj/", "/packages/",
        "/.vs/", "/dist/", "/build/", ".egg-info/",
    )
    for f in files:
        if not any(f.endswith(e) for e in code_exts):
            continue
        f_norm = f.replace("\\", "/").lower()
        if any(noise in f_norm for noise in noise_substrings):
            continue
        basename = f.replace("\\", "/").rsplit("/", 1)[-1]
        if basename.startswith("gen_"):
            continue
        path = root / f
        try:
            size = path.stat().st_size
            if size > 10000:
                hotspots.append({"file": f, "size_kb": round(size / 1024, 1), "reason": "large file"})
        except Exception:
            continue
    return sorted(hotspots, key=lambda x: -x["size_kb"])[:10]


def analyze_repo(root: Path) -> Dict:
    files = scan_tracked_files(root)
    return {
        "total_files": len(files),
        "stack": detect_stack(files),
        "modules": map_modules(files),
        "hotspots": detect_hotspots(root, files),
    }
