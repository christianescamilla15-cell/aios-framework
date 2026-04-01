"""Hooks — real event-driven automation (git hooks + scripts)."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Dict, List


HOOK_TEMPLATES = {
    "pre-commit": {
        "description": "Runs before git commit — lint + tests",
        "script": """#!/bin/sh
# AIOS pre-commit hook
echo "[AIOS] Running pre-commit checks..."

# Lint
{lint_cmd}

# Quick tests
{test_cmd}

echo "[AIOS] Pre-commit checks passed."
""",
    },
    "post-save-tests": {
        "description": "Run relevant tests after file save",
        "script": """#!/bin/sh
# AIOS post-save hook — run tests for changed files
CHANGED=$(git diff --name-only --cached 2>/dev/null || echo "")
if echo "$CHANGED" | grep -q ".py$"; then
    echo "[AIOS] Python files changed — running pytest..."
    {test_cmd}
fi
if echo "$CHANGED" | grep -q ".jsx\\|.tsx\\|.js$"; then
    echo "[AIOS] JS files changed — running vitest..."
    npx vitest run --reporter=dot 2>/dev/null
fi
""",
    },
    "security-scan": {
        "description": "Scan for secrets before commit",
        "script": """#!/bin/sh
# AIOS security scan
echo "[AIOS] Scanning for secrets..."
FOUND=0
for pattern in "sk-ant-" "gsk_" "AKIA" "aws_secret" "private_key" "password="; do
    if git diff --cached --name-only | xargs grep -l "$pattern" 2>/dev/null; then
        echo "[AIOS] WARNING: Possible secret found matching '$pattern'"
        FOUND=1
    fi
done
if [ $FOUND -eq 1 ]; then
    echo "[AIOS] BLOCKED: Remove secrets before committing."
    exit 1
fi
echo "[AIOS] No secrets found."
""",
    },
}


def install_git_hook(root: Path, hook_name: str, stack: str = "python") -> bool:
    """Install a git hook."""
    hooks_dir = root / ".git" / "hooks"
    if not hooks_dir.exists():
        return False

    lint_cmd = {
        "python": "python -m py_compile $(git diff --cached --name-only --diff-filter=ACM | grep '.py$') 2>/dev/null",
        "react": "npx eslint --quiet $(git diff --cached --name-only --diff-filter=ACM | grep '.jsx$\\|.tsx$') 2>/dev/null",
    }.get(stack, "echo 'No lint configured'")

    test_cmd = {
        "python": "python -m pytest --tb=short -q 2>/dev/null || true",
        "react": "npx vitest run --reporter=dot 2>/dev/null || true",
    }.get(stack, "echo 'No tests configured'")

    template = HOOK_TEMPLATES.get(hook_name)
    if not template:
        return False

    script = template["script"].format(lint_cmd=lint_cmd, test_cmd=test_cmd)

    # Map hook names to git hook filenames
    git_hook_name = {
        "pre-commit": "pre-commit",
        "security-scan": "pre-commit",
        "post-save-tests": "post-commit",
    }.get(hook_name, "pre-commit")

    hook_path = hooks_dir / git_hook_name
    hook_path.write_text(script, encoding="utf-8")
    hook_path.chmod(0o755)
    return True


def list_hooks(root: Path) -> List[Dict]:
    """List available and installed hooks."""
    hooks_dir = root / ".git" / "hooks"
    installed = set()
    if hooks_dir.exists():
        for f in hooks_dir.iterdir():
            if f.is_file() and not f.name.endswith(".sample"):
                installed.add(f.name)

    result = []
    for name, tmpl in HOOK_TEMPLATES.items():
        git_name = {"pre-commit": "pre-commit", "security-scan": "pre-commit", "post-save-tests": "post-commit"}.get(name, "pre-commit")
        result.append({
            "name": name,
            "description": tmpl["description"],
            "git_hook": git_name,
            "installed": git_name in installed,
        })
    return result
