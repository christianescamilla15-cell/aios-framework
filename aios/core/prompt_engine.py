"""Prompt Engine — generates execution prompts per mode."""
from __future__ import annotations


def build_execution_prompt(mode: str, task: str, spec_path: str) -> str:
    """Generate the CloudCode execution prompt for a given mode."""

    if mode == "BUGFIX":
        return f"""Act as a Kiro-style spec-driven system for BUGFIX work.
Do not jump to the fix. Analyze, isolate, document, then implement.
Phases: Context Discovery -> Root Cause -> Surgical Fix -> Regression Tests -> Release Safety
Rules: surgical fixes, no unrelated refactors, add regression tests, document root cause.

Task: {task}
Spec: {spec_path}
Read /ai-memory/ first, then work through {spec_path}."""

    if mode == "FEATURE":
        return f"""Act as a Kiro-style spec-driven system for FEATURE development.
Do not code first. Follow: Context -> Spec Review -> Agent Execution -> Implementation -> Validation -> Release.
Rules: preserve existing behavior, incremental additions, tests for critical paths.

Task: {task}
Spec: {spec_path}
Read /ai-memory/ first, then work through {spec_path}."""

    if mode == "MIGRATION":
        return f"""Act as a Kiro-style enterprise MIGRATION system.
Follow: Discovery -> Spec Review -> Phased Execution -> Validation -> Deploy.
Rules: strangler pattern, no big-bang rewrites, backward compatibility, rollback per phase.

Task: {task}
Spec: {spec_path}
Read /ai-memory/ first, then work through {spec_path}."""

    if mode == "LEGACY_MODERNIZATION":
        return f"""Act as a Kiro-style LEGACY MODERNIZATION system.
Follow: Discovery -> Dependency Mapping -> Incremental Refactor -> Tests -> Stabilization -> Docs.
Rules: stability first, avoid large rewrites, tests around fragile areas, quick wins first.

Task: {task}
Spec: {spec_path}
Read /ai-memory/ first, then work through {spec_path}."""

    return f"Task: {task}\nSpec: {spec_path}"
