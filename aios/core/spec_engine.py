"""Spec Engine — generates structured specs from task + mode + repo context."""
from __future__ import annotations

import re
from pathlib import Path
from typing import List


def slugify(text: str, max_len: int = 40) -> str:
    """v1.5.0 · max_len reduced from 90 to 40 chars (avoids unwieldy folder names).

    For long task titles, append short hash for uniqueness.
    """
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = re.sub(r"-{2,}", "-", text).strip("-")
    if not text:
        return "untitled"
    if len(text) > max_len:
        # Truncate + append short hash for uniqueness
        import hashlib
        h = hashlib.sha1(text.encode()).hexdigest()[:6]
        text = text[:max_len].rstrip("-") + "-" + h
    return text


def get_prefix(mode: str) -> str:
    return {"BUGFIX": "bugfix", "FEATURE": "feature", "MIGRATION": "migration", "LEGACY_MODERNIZATION": "legacy"}[mode]


def get_spec_files(mode: str) -> List[str]:
    base = {
        "BUGFIX": ["bugfix.md", "design.md", "tasks.md", "validation.md", "rollback.md", "risks.md"],
        "FEATURE": ["requirements.md", "design.md", "tasks.md", "validation.md", "rollout.md", "risks.md"],
        "MIGRATION": ["requirements.md", "design.md", "tasks.md", "validation.md", "rollout.md", "rollback.md", "risks.md"],
        "LEGACY_MODERNIZATION": ["requirements.md", "design.md", "tasks.md", "modernization-roadmap.md", "validation.md", "rollback.md", "risks.md"],
    }
    return base.get(mode, base["FEATURE"])


def file_template(filename: str, mode: str, task: str, context: str | None = None) -> str:
    title = f"{mode.replace('_', ' ').title()} - {task}"
    ctx = f"\n## Context\n{context}\n" if context else ""

    templates = {
        "bugfix.md": f"# {title}\n\n## Problem Statement\n\n## Symptoms\n\n## Expected Behavior\n\n## Actual Behavior\n\n## Reproduction Steps\n1.\n2.\n\n## Likely Root Cause\n\n## Acceptance Criteria\n- [ ] Bug resolved\n- [ ] No regressions\n- [ ] Tests added\n{ctx}",
        "requirements.md": f"""# {title}

## Objective

## User Impact

## Requirements (EARS Format)

### Ubiquitous (always true)
<!-- The system SHALL [action] -->

### Event-Driven (when something happens)
<!-- WHEN [event], the system SHALL [action] -->

### State-Driven (while in a state)
<!-- WHILE [state], the system SHALL [action] -->

### Unwanted Behavior (handling failures)
<!-- IF [condition], THEN the system SHALL [action] -->

### Optional (conditional features)
<!-- WHERE [feature is enabled], the system SHALL [action] -->

## Non-Functional Requirements
- Performance:
- Security:
- Reliability:
- Scalability:

## Acceptance Criteria
- [ ]
- [ ]
- [ ]

## Out of Scope
{ctx}""",
        "design.md": f"# {title}\n\n## Current State\n\n## Proposed Design\n\n## Architecture Impact\n\n## Tradeoffs\n\n## Risks\n{ctx}",
        "tasks.md": f"# {title}\n\n## Tasks\n\n### T1\n- Description:\n- Owner Agent:\n- Dependencies:\n- Validation:\n- Risk: low/medium/high\n\n### T2\n- Description:\n- Owner Agent:\n- Dependencies:\n- Validation:\n- Risk: low/medium/high\n{ctx}",
        "validation.md": f"# {title}\n\n## Checklist\n- [ ] Scope correct\n- [ ] Tests identified\n- [ ] Edge cases reviewed\n\n## Test Matrix\n- Unit:\n- Integration:\n- Regression:\n{ctx}",
        "rollback.md": f"# {title}\n\n## Rollback Conditions\n\n## Rollback Steps\n1.\n2.\n\n## Post-Rollback Verification\n{ctx}",
        "rollout.md": f"# {title}\n\n## Rollout Plan\n\n## Deployment Steps\n1.\n2.\n\n## Post-Deploy Checks\n- [ ] Main flow works\n- [ ] Logs healthy\n{ctx}",
        "risks.md": f"# {title}\n\n## Known Risks\n\n## Mitigations\n\n## Open Questions\n{ctx}",
        "modernization-roadmap.md": f"# {title}\n\n## Quick Wins\n\n## Medium-Term Cleanup\n\n## High-Risk Refactors\n\n## Future Migration Readiness\n{ctx}",
    }
    return templates.get(filename, f"# {title}\n{ctx}")


def find_app_memory(root: Path, task: str) -> str:
    """v1.6.0 NEW · search apps_code/<app>/.memory/ for files matching task tokens.

    Returns concatenated memory content (max 10K chars) used to autofill spec.
    """
    apps_root = root / "apps_code"
    if not apps_root.exists():
        return ""

    # v1.6.0 fix · use [a-z0-9]+ (NOT \w+) so underscore separates tokens
    # ("01_sicofav" → {01, sicofav}, not {01_sicofav})
    task_tokens = set(re.findall(r"[a-z0-9]+", task.lower()))
    if not task_tokens:
        return ""

    candidates = []
    for app_dir in apps_root.iterdir():
        if not app_dir.is_dir() or app_dir.name.startswith("."):
            continue
        # Match app folder name to task tokens (e.g. "01_sicofav" matches task "sicofav refactor")
        app_tokens = set(re.findall(r"[a-z0-9]+", app_dir.name.lower()))
        score = len(task_tokens & app_tokens) / len(task_tokens) if task_tokens else 0
        if score < 0.1:
            continue
        memory_dir = app_dir / ".memory"
        if not memory_dir.exists():
            continue
        for f in memory_dir.glob("*.md"):
            try:
                candidates.append((score, f.read_text(encoding="utf-8")))
            except: pass

    if not candidates:
        return ""

    # Best matching app · concatenate its memory (max 10K chars)
    candidates.sort(key=lambda x: -x[0])
    combined = ""
    for _, content in candidates[:3]:
        combined += content + "\n\n---\n\n"
        if len(combined) > 10000:
            break
    return combined[:10000]


def autofill_section(memory: str, section_keyword: str) -> str | None:
    """v1.6.0 · extract section content from memory by keyword."""
    if not memory:
        return None
    pattern = rf"##\s*{section_keyword}[^\n]*\n(.*?)(?=\n##\s|\Z)"
    m = re.search(pattern, memory, re.DOTALL | re.IGNORECASE)
    if m:
        content = m.group(1).strip()
        if len(content) > 30:
            return content[:1500]  # cap
    return None


def file_template_with_memory(filename: str, mode: str, task: str,
                               context: str | None, memory: str) -> str:
    """v1.6.0 · enhanced template that autofills sections from app memory."""
    base = file_template(filename, mode, task, context)
    if not memory:
        return base

    # Try to extract relevant sections from memory
    if filename == "requirements.md":
        # Inject Objective if memory has stack/identity info
        identity = autofill_section(memory, "Identidad") or autofill_section(memory, "Stack")
        if identity:
            objective = (
                f"Estabilizar y modernizar este aplicativo según el plan AMX. "
                f"Cerrar hallazgos del assessment + scan deep. "
                f"Cumplir constraints AMX (ECS prohibido · Akamai mandatorio · 4 escaneos pre-prod · KMS AMX · "
                f"Vault para credenciales). Migrar a stack target moderno preservando funcionalidad operativa.\n\n"
                f"Contexto AS-IS:\n{identity[:600]}"
            )
            base = re.sub(r"(##\s*Objective\s*\n)\s*\n", rf"\1\n{objective}\n\n", base, count=1)

    elif filename == "risks.md":
        # Try to inject hallazgos from memory
        hallazgos = autofill_section(memory, "hallazgos") or autofill_section(memory, "CRITICAL")
        if hallazgos:
            base = re.sub(
                r"(##\s*Known Risks\s*\n)\s*\n",
                rf"\1\nHallazgos detectados (de memoria app):\n\n{hallazgos[:1200]}\n\n",
                base, count=1
            )

    elif filename == "design.md":
        # Inject Current State from memory
        stack_info = autofill_section(memory, "Stack") or autofill_section(memory, "Identidad")
        if stack_info:
            base = re.sub(
                r"(##\s*Current State\s*\n)\s*\n",
                rf"\1\n{stack_info[:1000]}\n\n",
                base, count=1
            )

    return base


def create_spec(root: Path, mode: str, task: str, context: str | None = None,
                autofill_from_memory: bool = True) -> Path:
    """Create a full spec folder with all required files.

    v1.6.0 · autofill_from_memory (default True) loads apps_code/<app>/.memory/
    and pre-fills Objective, Current State, Known Risks sections.
    """
    prefix = get_prefix(mode)
    slug = f"{prefix}-{slugify(task)}"
    spec_dir = root / "specs" / slug

    # v1.6.0 · load app memory if available
    memory = find_app_memory(root, task) if autofill_from_memory else ""

    spec_dir.mkdir(parents=True, exist_ok=True)
    for filename in get_spec_files(mode):
        path = spec_dir / filename
        if not path.exists():
            content = file_template_with_memory(filename, mode, task, context, memory) if memory \
                      else file_template(filename, mode, task, context)
            path.write_text(content, encoding="utf-8")

    return spec_dir
