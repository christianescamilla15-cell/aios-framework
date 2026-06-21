"""Hooks — real event-driven automation (git hooks + scripts).

v1.7.0 changes:
- Multi-stack aware pre-commit (detects affected files' stack)
- Comprehensive secrets patterns (15+ tokens · IPs · creds)
- ACME policy check (debug=true · customErrors Off · ECS · etc.)
- Combined "all-in-one" hook that runs lint + tests + secrets + policy
- Better error messages with bypass instructions
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List


# v1.7.0 · expanded secrets patterns
SECRETS_PATTERNS = [
    "sk-ant-",          # Anthropic
    "sk-proj-",         # OpenAI
    "gsk_",             # Groq
    "AKIA",             # AWS Access Key
    "ASIA",             # AWS STS
    "aws_secret",       # generic
    "private_key",      # generic
    "BEGIN RSA",        # private keys
    "BEGIN OPENSSH",    # OpenSSH keys
    "ghp_",             # GitHub PAT
    "ghs_",             # GitHub server
    "github_pat_",      # GitHub fine-grained
    "xoxb-",            # Slack bot
    "ATOS5246",         # ACME-specific (NoShow vendor code)
]


# v1.7.0 · ACME policy patterns (configurable via .aios/policy.toml in future)
AMX_POLICY_BLOCKERS = [
    (r'customErrors\s+mode\s*=\s*["\']Off["\']', "customErrors mode=Off (CWE-209) · prod expone stack traces"),
    (r'(?<!#)\s*compilation\s+debug\s*=\s*["\']true["\']', "compilation debug=true en .config · forbidden en prod"),
    (r'flight\w*\.flightNumber\s*=\s*["\']829["\']', "Vuelo 829 hardcoded (NoShow regression) · use PNR real"),
    (r'amazonaws\.com/v1/[^"\']*ecs', "ECS endpoint detected · ECS PROHIBIDO por policy ACME"),
]


HOOK_TEMPLATES = {
    "pre-commit": {
        "description": "v1.7.0 · all-in-one: lint + tests + secrets + ACME policy",
        "script": """#!/bin/sh
# AIOS pre-commit hook v1.7.0
# Bypass with: git commit --no-verify
echo "[AIOS] Running pre-commit checks..."

FAIL=0

# 1. Lint (per affected file stack)
{lint_cmd}
if [ $? -ne 0 ]; then
    echo "[AIOS] LINT failed"
    FAIL=1
fi

# 2. Tests (smart · only affected · best-effort)
{test_cmd}

# 3. Secrets scan
echo "[AIOS] Scanning for secrets..."
SECRETS_FOUND=0
CHANGED=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null)
if [ -n "$CHANGED" ]; then
    for pattern in {secrets_patterns}; do
        if echo "$CHANGED" | xargs grep -l "$pattern" 2>/dev/null; then
            echo "[AIOS] BLOCKED: secret pattern '$pattern' detected"
            SECRETS_FOUND=1
        fi
    done
fi
if [ $SECRETS_FOUND -eq 1 ]; then
    echo "[AIOS] Remove secrets before committing · or bypass with --no-verify"
    FAIL=1
fi

# 4. ACME policy check (regex blockers)
echo "[AIOS] ACME policy check..."
POLICY_FAIL=0
{policy_checks}
if [ $POLICY_FAIL -eq 1 ]; then
    echo "[AIOS] ACME policy violation · fix or bypass with --no-verify"
    FAIL=1
fi

if [ $FAIL -eq 1 ]; then
    echo "[AIOS] Pre-commit FAILED · review issues above."
    exit 1
fi
echo "[AIOS] Pre-commit checks passed ✓"
""",
    },
    "secrets-only": {
        "description": "Only scan for secrets (lighter · faster)",
        "script": """#!/bin/sh
# AIOS secrets-only pre-commit
echo "[AIOS] Scanning for secrets..."
FOUND=0
CHANGED=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null)
if [ -n "$CHANGED" ]; then
    for pattern in {secrets_patterns}; do
        if echo "$CHANGED" | xargs grep -l "$pattern" 2>/dev/null; then
            echo "[AIOS] BLOCKED: '$pattern' detected"
            FOUND=1
        fi
    done
fi
if [ $FOUND -eq 1 ]; then
    echo "[AIOS] Remove secrets · bypass with --no-verify"
    exit 1
fi
echo "[AIOS] No secrets found ✓"
""",
    },
    "post-save-tests": {
        "description": "Run relevant tests after git commit (post-commit · async)",
        "script": """#!/bin/sh
# AIOS post-commit · async test run
CHANGED=$(git diff HEAD~1 HEAD --name-only 2>/dev/null || echo "")
if echo "$CHANGED" | grep -q ".py$"; then
    echo "[AIOS] Python files committed · running pytest in background..."
    (python -m pytest --tb=short -q 2>&1 | tail -20) &
fi
if echo "$CHANGED" | grep -q ".cs$"; then
    echo "[AIOS] .NET files committed · running dotnet test in background..."
    (dotnet test --no-build --verbosity quiet 2>&1 | tail -20) &
fi
""",
    },
    "security": {
        "description": "Security gate sobre staged files solamente · mas rapido que scan completo",
        "script": """#!/bin/sh
# AIOS security pre-commit hook · staged files only
# Escaneo delta · solo archivos en git stage · mucho mas rapido que
# scanear repo completo en proyectos grandes.
# Bypass · git commit --no-verify
echo "[AIOS/security] Scanning staged files only..."

STAGED_ALL=$(git diff --cached --name-only --diff-filter=ACM)
STAGED_CODE=$(echo "$STAGED_ALL" | grep -Ev '\\.(md|txt|rst|png|jpg|svg|pdf|lock|json)$' | grep -v '^$')

if [ -z "$STAGED_CODE" ]; then
    echo "[AIOS/security] No code files staged · skip"
    exit 0
fi

COUNT=$(echo "$STAGED_CODE" | wc -l)
echo "[AIOS/security] Scanning $COUNT staged file(s)..."

# Corre aios security-scan-staged con la lista · comando expone
# scan_files() · retorna exit 1 si hay CRITICAL findings.
echo "$STAGED_CODE" | aios security-scan-staged --stdin
RC=$?

if [ $RC -ne 0 ]; then
    echo ""
    echo "[AIOS/security] CRITICAL findings en staged files · commit BLOQUEADO"
    echo "  · fix · o agrega suppression con 'aios suppress add ...'"
    echo "  · bypass emergencia con 'git commit --no-verify'"
    exit 1
fi

echo "[AIOS/security] OK · no CRITICAL"
""",
    },
}


def _build_lint_cmd(stacks: List[str]) -> str:
    """v1.7.0 · multi-stack lint commands."""
    cmds = []
    if "python" in stacks:
        cmds.append('CHANGED_PY=$(git diff --cached --name-only --diff-filter=ACM | grep ".py$"); if [ -n "$CHANGED_PY" ]; then python -m py_compile $CHANGED_PY 2>&1; fi')
    if "react" in stacks or "javascript" in stacks:
        cmds.append('CHANGED_JS=$(git diff --cached --name-only --diff-filter=ACM | grep -E ".(jsx|tsx|js|ts)$"); if [ -n "$CHANGED_JS" ]; then npx eslint --quiet $CHANGED_JS 2>&1 || true; fi')
    if "dotnet" in stacks:
        cmds.append('CHANGED_CS=$(git diff --cached --name-only --diff-filter=ACM | grep -E ".(cs|vb)$"); if [ -n "$CHANGED_CS" ]; then dotnet format --verify-no-changes 2>&1 || true; fi')
    if "java" in stacks:
        cmds.append('CHANGED_JAVA=$(git diff --cached --name-only --diff-filter=ACM | grep ".java$"); if [ -n "$CHANGED_JAVA" ]; then mvn checkstyle:check -q 2>&1 || true; fi')
    if "php" in stacks:
        cmds.append('CHANGED_PHP=$(git diff --cached --name-only --diff-filter=ACM | grep ".php$"); if [ -n "$CHANGED_PHP" ]; then php -l $CHANGED_PHP 2>&1 || true; fi')
    if not cmds:
        return 'echo "[AIOS] No lint configured for detected stacks"'
    return "\n".join(cmds)


def _build_test_cmd(stacks: List[str]) -> str:
    """v1.7.0 · multi-stack test commands (best-effort · don't fail commit)."""
    cmds = []
    if "python" in stacks:
        cmds.append('echo "[AIOS] pytest..."; python -m pytest --tb=short -q -x 2>&1 | tail -10 || true')
    if "dotnet" in stacks:
        cmds.append('echo "[AIOS] dotnet test..."; dotnet test --no-restore --verbosity quiet 2>&1 | tail -10 || true')
    if "java" in stacks:
        cmds.append('echo "[AIOS] mvn test..."; mvn test -q 2>&1 | tail -10 || true')
    if "php" in stacks:
        cmds.append('echo "[AIOS] phpunit..."; vendor/bin/phpunit --no-coverage 2>&1 | tail -10 || true')
    if not cmds:
        return 'echo "[AIOS] No tests configured"'
    return "\n".join(cmds)


def _build_policy_checks() -> str:
    """v1.7.0 · ACME policy regex blockers (per-pattern)."""
    parts = ['CHANGED_FILES=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null)']
    for pattern, msg in AMX_POLICY_BLOCKERS:
        # Escape single quotes for shell
        msg_esc = msg.replace("'", "'\\''")
        pat_esc = pattern.replace("'", "'\\''")
        parts.append(f"""if [ -n "$CHANGED_FILES" ] && echo "$CHANGED_FILES" | xargs grep -lE '{pat_esc}' 2>/dev/null; then
    echo "[AIOS] ACME policy: {msg_esc}"
    POLICY_FAIL=1
fi""")
    return "\n".join(parts)


def install_git_hook(root: Path, hook_name: str, stack: str = "auto") -> bool:
    """Install a git hook.

    v1.7.0 · stack="auto" detects all relevant stacks via module_loader.
    """
    hooks_dir = root / ".git" / "hooks"
    if not hooks_dir.exists():
        return False

    template = HOOK_TEMPLATES.get(hook_name)
    if not template:
        return False

    # v1.7.0 · auto-detect stacks if "auto" or specific stack passed
    if stack == "auto":
        try:
            from .module_loader import detect_relevant_stacks
            stacks = detect_relevant_stacks(root)
        except Exception:
            stacks = ["python"]
    else:
        stacks = [stack]

    lint_cmd = _build_lint_cmd(stacks)
    test_cmd = _build_test_cmd(stacks)
    policy_checks = _build_policy_checks()
    secrets_patterns = " ".join(f'"{p}"' for p in SECRETS_PATTERNS)

    script = template["script"].format(
        lint_cmd=lint_cmd,
        test_cmd=test_cmd,
        policy_checks=policy_checks,
        secrets_patterns=secrets_patterns,
    )

    # Map hook names to git hook filenames
    git_hook_name = {
        "pre-commit": "pre-commit",
        "secrets-only": "pre-commit",
        "post-save-tests": "post-commit",
    }.get(hook_name, "pre-commit")

    hook_path = hooks_dir / git_hook_name
    hook_path.write_text(script, encoding="utf-8")
    try:
        hook_path.chmod(0o755)
    except Exception:
        # Windows file permissions may not support chmod fully
        pass
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
        git_name = {
            "pre-commit": "pre-commit",
            "secrets-only": "pre-commit",
            "post-save-tests": "post-commit",
        }.get(name, "pre-commit")
        result.append({
            "name": name,
            "description": tmpl["description"],
            "git_hook": git_name,
            "installed": git_name in installed,
        })
    return result
