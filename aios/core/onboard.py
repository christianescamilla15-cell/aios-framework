"""Onboard Wizard — guides new users through AIOS setup for enterprise repos."""
from __future__ import annotations

from pathlib import Path
from typing import Dict

from .repo_analyzer import analyze_repo
from .monorepo import detect_services, is_monorepo
from .memory_engine import ensure_memory
from .config import init_config
from .module_loader import detect_relevant_stacks
from .steering import create_steering_file


def run_onboard(root: Path) -> Dict:
    """Full onboarding for a new project. Returns report."""
    report = {"steps": [], "warnings": [], "next_steps": []}

    # Step 1: Analyze repo
    analysis = analyze_repo(root)
    report["steps"].append(f"Analyzed repo: {analysis['total_files']} files, stack: {', '.join(analysis['stack'])}")

    # Step 2: Detect monorepo
    mono = is_monorepo(root)
    if mono:
        services = detect_services(root)
        report["steps"].append(f"Monorepo detected: {len(services)} services")
        for s in services:
            report["steps"].append(f"  - {s['name']} [{s['type']}]")
    else:
        report["steps"].append("Single-service project")

    # Step 3: Create AIOS structure
    ensure_memory(root)
    report["steps"].append("ai-memory/ initialized")

    # Step 4: Detect stacks
    stacks = detect_relevant_stacks(root)
    report["steps"].append(f"Stacks detected: {', '.join(stacks)}")

    # Step 5: Create config
    config = init_config(root, project_name=root.name, modules=stacks)
    report["steps"].append(f"Config created: .aios/config.json")

    # Step 6: Auto-generate steering files
    _generate_steering(root, analysis, stacks)
    report["steps"].append("Steering files generated")

    # Step 7: Generate product context
    _generate_product_context(root, analysis, stacks, mono)
    report["steps"].append("Product context generated")

    # Step 8: Identify warnings
    if not analysis["stack"]:
        report["warnings"].append("No tech stack detected — add project files")
    if analysis["total_files"] == 0:
        report["warnings"].append("No files found — is this the right directory?")
    hotspots = analysis.get("hotspots", [])
    if hotspots:
        report["warnings"].append(f"{len(hotspots)} large files detected (potential hotspots)")

    # Step 9: Next steps
    report["next_steps"] = [
        "Run: aios boot (to start a session)",
        "Run: aios task --task 'your first task'",
        "Edit ai-memory/product_context.md with your project details",
        "Edit ai-memory/tech_context.md with your stack details",
        "Run: aios analyze (to see full repo analysis)",
        "Run: aios guide (for troubleshooting help)",
    ]

    return report


def _generate_steering(root: Path, analysis: Dict, stacks: list) -> None:
    """Auto-generate relevant steering files."""
    # Project standards (always)
    create_steering_file(root, "project-standards", f"""# Project Standards

## Stack
{', '.join(analysis['stack']) or 'Not detected'}

## Conventions
- Follow existing code patterns
- Write tests for new functionality
- Use environment variables for secrets
- Document architecture decisions
""")

    # Python steering (conditional)
    if "python" in stacks:
        create_steering_file(root, "python-conventions", """# Python Conventions
- Use type hints on all functions
- Use async/await for I/O
- Pydantic v2 for data validation
- pytest for testing
- No print() in production code
""", inclusion="fileMatch", file_match_pattern="*.py")

    # React steering (conditional)
    if "react" in stacks:
        create_steering_file(root, "frontend-standards", """# Frontend Standards
- Functional components only
- Custom hooks for shared logic
- Error boundaries for critical sections
- No prop drilling beyond 2 levels
""", inclusion="fileMatch", file_match_pattern="*.jsx")

    # Git workflow (always)
    create_steering_file(root, "git-workflow", """# Git Workflow
- Descriptive commit messages
- Never force push to main
- PRs require review or CI pass
- Keep commits focused and small
""")


def _generate_product_context(root: Path, analysis: Dict, stacks: list, is_mono: bool) -> None:
    """Generate initial product context from repo analysis."""
    content = f"""# Product Context

## Project
{root.name}

## Type
{'Monorepo' if is_mono else 'Single service'}

## Detected Stack
{', '.join(analysis['stack']) or 'Unknown'}

## Modules
{chr(10).join(f'- {m} ({c} files)' for m, c in list(analysis['modules'].items())[:10])}

## Hotspots (large files — review carefully before changing)
{chr(10).join(f'- {h["file"]} ({h["size_kb"]}KB)' for h in analysis.get('hotspots', [])[:5])}

## TODO: Fill in manually
- What does this project do?
- Who are the users?
- What are the critical workflows?
- What are the business constraints?
"""
    (root / "ai-memory" / "product_context.md").write_text(content, encoding="utf-8")
