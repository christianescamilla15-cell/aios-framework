#!/usr/bin/env python3
"""Bootstrap — install the Kiro-style system into any project in seconds."""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path


SYSTEM_DIR = Path(__file__).parent.parent


def bootstrap(target: Path) -> None:
    """Copy the entire kiro-system into a target project."""
    target = target.resolve()

    # Copy ai-system (prompts)
    src_system = SYSTEM_DIR / "ai-system"
    dst_system = target / "ai-system"
    if src_system.exists():
        if dst_system.exists():
            print(f"  /ai-system already exists — skipping (won't overwrite)")
        else:
            shutil.copytree(src_system, dst_system)
            print(f"  /ai-system created ({len(list(dst_system.glob('*.md')))} files)")

    # Copy scripts
    src_scripts = SYSTEM_DIR / "scripts"
    dst_scripts = target / "scripts"
    dst_scripts.mkdir(exist_ok=True)
    for script in ["new_task.py", "session_refresh.py"]:
        src = src_scripts / script
        dst = dst_scripts / script
        if src.exists() and not dst.exists():
            shutil.copy2(src, dst)
            print(f"  /scripts/{script} created")
        elif dst.exists():
            print(f"  /scripts/{script} already exists — skipping")

    # Create ai-memory with defaults
    memory_dir = target / "ai-memory"
    memory_dir.mkdir(exist_ok=True)
    defaults = {
        "product_context.md": "# Product Context\n\nDescribe the product, users, and critical workflows.\n",
        "tech_context.md": "# Tech Context\n\nDescribe the stack, tooling, and infrastructure.\n",
        "architecture_context.md": "# Architecture Context\n\nDescribe modules, services, and dependencies.\n",
        "active_workstream.md": "# Active Workstream\n\nNo active workstream yet.\n",
        "recent_decisions.md": "# Recent Decisions\n\n",
        "known_risks.md": "# Known Risks\n\n",
    }
    created = 0
    for name, content in defaults.items():
        path = memory_dir / name
        if not path.exists():
            path.write_text(content, encoding="utf-8")
            created += 1
    print(f"  /ai-memory created ({created} new files, {len(defaults) - created} existing)")

    # Create specs and docs
    for d in ["specs", "docs"]:
        (target / d).mkdir(exist_ok=True)
        print(f"  /{d} ready")

    print(f"\n  Kiro system installed in: {target}")
    print(f"  Next: run `python scripts/new_task.py --task 'your task'`")


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap Kiro-style system into a project")
    parser.add_argument("--target", required=True, help="Target project directory")
    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"  Target directory does not exist: {target}")
        return

    print(f"\n  Bootstrapping Kiro system into: {target}\n")
    bootstrap(target)


if __name__ == "__main__":
    main()
