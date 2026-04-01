"""Spec Engine — generates structured specs from task + mode + repo context."""
from __future__ import annotations

import re
from pathlib import Path
from typing import List


def slugify(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return re.sub(r"-{2,}", "-", text).strip("-")[:90] or "untitled"


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


def create_spec(root: Path, mode: str, task: str, context: str | None = None) -> Path:
    """Create a full spec folder with all required files."""
    prefix = get_prefix(mode)
    slug = f"{prefix}-{slugify(task)}"
    spec_dir = root / "specs" / slug

    spec_dir.mkdir(parents=True, exist_ok=True)
    for filename in get_spec_files(mode):
        path = spec_dir / filename
        if not path.exists():
            path.write_text(file_template(filename, mode, task, context), encoding="utf-8")

    return spec_dir
