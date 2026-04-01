"""Mode Router — detects task mode using keyword scoring + git diff + repo signals."""
from __future__ import annotations

import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

VALID_MODES = {"BUGFIX", "FEATURE", "MIGRATION", "LEGACY_MODERNIZATION"}

KEYWORD_MAP = {
    "MIGRATION": {
        "migrate": 5, "migration": 5, "move to aws": 5, "move to cloud": 5,
        "monolith": 4, "microservice": 5, "microservices": 5, "dockerize": 4,
        "containerize": 4, "ecs": 3, "eks": 3, "kubernetes": 4, "rds": 3,
        "terraform": 3, "database migration": 5, "rewrite in": 4, "port to": 4,
        "on-prem": 4, "framework migration": 5, "ci/cd modernization": 4,
    },
    "LEGACY_MODERNIZATION": {
        "legacy": 5, "technical debt": 5, "stabilize": 4, "cleanup": 4,
        "decouple": 4, "reduce coupling": 5, "refactor old": 4, "modernize": 5,
        "document old": 4, "improve test coverage": 4, "tightly coupled": 4,
        "prepare for future migration": 5, "hard to maintain": 3,
    },
    "BUGFIX": {
        "fix": 4, "bug": 4, "broken": 5, "crash": 5, "failing": 4,
        "error": 4, "regression": 5, "white screen": 5, "not working": 5,
        "doesn't work": 5, "misaligned": 4, "incorrect": 4, "layout broken": 5,
    },
    "FEATURE": {
        "add": 3, "create": 3, "build": 3, "new feature": 5, "new module": 4,
        "new dashboard": 4, "analytics": 3, "integration": 3, "new endpoint": 4,
        "new page": 4, "export": 3, "automation": 3,
    },
}

# Git diff patterns for mode detection
GIT_PATTERNS = {
    "MIGRATION": {
        "dirs": ["infra/", "terraform/", "k8s/", "kubernetes/", "docker/", ".github/workflows/", "ci/"],
        "files": ["Dockerfile", "docker-compose", ".tf", "Jenkinsfile", "Procfile"],
        "weight": 3,
    },
    "BUGFIX": {
        "dirs": [],
        "files": [".test.", "_test.", ".spec."],
        "signals": ["small_change"],  # < 50 lines changed = likely bugfix
        "weight": 2,
    },
    "FEATURE": {
        "signals": ["new_files", "new_dirs"],  # new files/dirs = likely feature
        "weight": 2,
    },
    "LEGACY_MODERNIZATION": {
        "dirs": [],
        "files": [],
        "signals": ["large_refactor", "many_files_changed"],  # > 20 files = refactor
        "weight": 2,
    },
}


def score_from_text(task: str, context: str | None = None) -> Dict[str, int]:
    text = " ".join(p.strip().lower() for p in [task, context] if p and p.strip())
    scores = defaultdict(int)
    for mode, mapping in KEYWORD_MAP.items():
        for phrase, weight in mapping.items():
            if phrase in text:
                scores[mode] += weight
    return dict(scores)


def score_from_git(root: Path) -> Dict[str, int]:
    """Enhanced git diff analysis — checks changed files, new files, change size."""
    scores = defaultdict(int)
    if not root:
        return dict(scores)

    try:
        # Get changed files (last 3 commits or staged)
        diff_result = subprocess.run(
            ["git", "diff", "--name-status", "HEAD~3"],
            cwd=str(root), capture_output=True, text=True, timeout=5
        )
        if diff_result.returncode != 0:
            # Try staged changes
            diff_result = subprocess.run(
                ["git", "diff", "--name-status", "--cached"],
                cwd=str(root), capture_output=True, text=True, timeout=5
            )

        lines = diff_result.stdout.strip().split("\n") if diff_result.stdout.strip() else []

        new_files = 0
        modified_files = 0
        deleted_files = 0
        changed_files = []

        for line in lines:
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            status, filepath = parts[0], parts[-1]
            fl = filepath.lower()
            changed_files.append(fl)

            if status.startswith("A"):
                new_files += 1
            elif status.startswith("M"):
                modified_files += 1
            elif status.startswith("D"):
                deleted_files += 1

            # Check migration patterns
            for pattern in GIT_PATTERNS["MIGRATION"]["dirs"]:
                if pattern in fl:
                    scores["MIGRATION"] += GIT_PATTERNS["MIGRATION"]["weight"]
            for pattern in GIT_PATTERNS["MIGRATION"]["files"]:
                if pattern in fl:
                    scores["MIGRATION"] += GIT_PATTERNS["MIGRATION"]["weight"]

            # Check bugfix patterns (test files modified)
            for pattern in GIT_PATTERNS["BUGFIX"]["files"]:
                if pattern in fl:
                    scores["BUGFIX"] += GIT_PATTERNS["BUGFIX"]["weight"]

        # Signal analysis
        total_changed = len(changed_files)

        if new_files > 3 and new_files > modified_files:
            scores["FEATURE"] += 4  # Many new files = feature
        if total_changed < 5 and modified_files > 0:
            scores["BUGFIX"] += 2  # Small change = likely bugfix
        if total_changed > 20:
            scores["LEGACY_MODERNIZATION"] += 3  # Many files = refactor
        if deleted_files > 5:
            scores["LEGACY_MODERNIZATION"] += 2  # Cleanup

        # Check diff size
        stat_result = subprocess.run(
            ["git", "diff", "--stat", "HEAD~3"],
            cwd=str(root), capture_output=True, text=True, timeout=5
        )
        if stat_result.stdout:
            last_line = stat_result.stdout.strip().split("\n")[-1]
            insertions = re.search(r"(\d+) insertion", last_line)
            deletions = re.search(r"(\d+) deletion", last_line)
            total_lines = (int(insertions.group(1)) if insertions else 0) + (int(deletions.group(1)) if deletions else 0)

            if total_lines < 50:
                scores["BUGFIX"] += 2
            elif total_lines > 500:
                scores["LEGACY_MODERNIZATION"] += 2

    except Exception:
        pass

    return dict(scores)


def detect_mode(task: str, context: str | None = None, root: Path | None = None) -> Tuple[str, Dict[str, int]]:
    text_scores = score_from_text(task, context)
    git_scores = score_from_git(root) if root else {}

    combined = defaultdict(int)
    for s in [text_scores, git_scores]:
        for mode, score in s.items():
            combined[mode] += score

    if combined.get("MIGRATION", 0) >= 5:
        return "MIGRATION", dict(combined)
    if combined.get("LEGACY_MODERNIZATION", 0) >= 5 and combined.get("MIGRATION", 0) < 5:
        return "LEGACY_MODERNIZATION", dict(combined)
    if combined.get("BUGFIX", 0) >= 4 and combined.get("MIGRATION", 0) < 5:
        return "BUGFIX", dict(combined)

    best = max(combined, key=combined.get) if combined else "FEATURE"
    return (best if combined.get(best, 0) > 0 else "FEATURE"), dict(combined)
