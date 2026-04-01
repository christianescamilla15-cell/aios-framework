#!/usr/bin/env python3
"""AIOS CLI — AI Engineering Operating System v0.9"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

# Support both installed (pip) and development mode
try:
    from aios.core.router import detect_mode
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from aios.core.router import detect_mode
from aios.core.spec_engine import create_spec, get_spec_files
from aios.core.memory_engine import (
    ensure_memory, read_memory, update_workstream,
    append_decision, append_risk, get_active_task,
)
from aios.core.repo_analyzer import analyze_repo
from aios.core.release_gate import check_release_readiness
from aios.core.prompt_engine import build_execution_prompt
from aios.core.module_loader import list_stacks, run_stack_checks, detect_relevant_stacks, run_all_relevant_checks
from aios.core.config import load_config, init_config, save_config
from aios.core.monorepo import detect_services, detect_active_service, is_monorepo
from aios.core.guide import get_guide, get_topics
from aios.core.onboard import run_onboard
from aios.core.hooks import install_git_hook, list_hooks
from aios.core.mcp import write_mcp_config, list_available_servers
from aios.core.lockfile import acquire_lock, release_lock, check_lock
from aios.core.test_runner import find_affected_tests, run_tests
from aios.core.progress import track_progress
from aios.core.cache import invalidate_cache


def get_root(args) -> Path:
    return Path(getattr(args, "root", ".")).resolve()


# ═══════════════════════════════════════
# COMMANDS
# ═══════════════════════════════════════

def cmd_init(args):
    """Initialize AIOS in a project."""
    root = get_root(args)
    print(f"\n  Initializing AIOS in: {root}\n")

    # Copy ai-system templates
    template_dir = Path(__file__).parent.parent.parent / "ai-system"
    target_system = root / "ai-system"
    if template_dir.exists() and not target_system.exists():
        shutil.copytree(template_dir, target_system)
        print(f"  ai-system/ created ({len(list(target_system.glob('*.md')))} prompts)")
    elif target_system.exists():
        print(f"  ai-system/ already exists")

    # Create memory
    created = ensure_memory(root)
    print(f"  ai-memory/ ready ({created} new files)")

    # Create dirs
    for d in ["specs", "docs"]:
        (root / d).mkdir(exist_ok=True)
        print(f"  {d}/ ready")

    # Analyze repo
    analysis = analyze_repo(root)
    print(f"\n  Stack detected: {', '.join(analysis['stack']) or 'none'}")
    print(f"  Modules: {len(analysis['modules'])}")
    print(f"  Files: {analysis['total_files']}")
    print(f"  Hotspots: {len(analysis['hotspots'])}")

    print(f"\n  AIOS initialized. Run: aios task --task 'your task'\n")


def cmd_task(args):
    """Create a new task with auto-detection."""
    root = get_root(args)
    ensure_memory(root)

    if args.mode:
        mode, scores = args.mode, {}
    else:
        mode, scores = detect_mode(args.task, args.context, root)

    spec_dir = create_spec(root, mode, args.task, args.context)
    update_workstream(root, args.task, mode, str(spec_dir))
    append_decision(root, f"## Started {spec_dir.name}\n- Task: {args.task}\n- Mode: {mode}\n- Scores: {scores}")

    prompt = build_execution_prompt(mode, args.task, str(spec_dir))

    print(f"\n{'='*60}")
    print(f"  TASK CREATED")
    print(f"{'='*60}")
    print(f"  Mode   : {mode}")
    print(f"  Folder : {spec_dir}")
    print(f"  Files  : {', '.join(get_spec_files(mode))}")
    if scores:
        print(f"  Scores : {scores}")
    print(f"{'='*60}")
    print(f"\n  EXECUTION PROMPT:\n")
    print(prompt)
    print(f"\n{'='*60}\n")


def cmd_boot(args):
    """Start a session — load context and show status."""
    root = get_root(args)
    memory = read_memory(root)
    task = get_active_task(root)

    print(f"\n{'='*60}")
    print(f"  SESSION BOOT")
    print(f"{'='*60}")

    if task.get("task"):
        print(f"  Task  : {task['task']}")
        print(f"  Mode  : {task.get('mode', '?')}")
        print(f"  Phase : {task.get('phase', '?')}")
        print(f"  Spec  : {task.get('spec', '?')}")
    else:
        print(f"  No active task. Run: aios task --task 'description'")

    # Show risks
    risks = memory.get("known_risks.md", "")
    risk_lines = [l for l in risks.splitlines() if l.strip() and not l.startswith("#")]
    if risk_lines:
        print(f"\n  Risks ({len(risk_lines)}):")
        for r in risk_lines[:5]:
            print(f"    {r.strip()}")

    # Show recent decisions
    decisions = memory.get("recent_decisions.md", "")
    dec_lines = [l for l in decisions.splitlines() if l.startswith("## ")]
    if dec_lines:
        print(f"\n  Recent decisions ({len(dec_lines)}):")
        for d in dec_lines[-3:]:
            print(f"    {d.strip()}")

    print(f"\n{'='*60}\n")


def cmd_refresh(args):
    """End session — update memory."""
    root = get_root(args)
    task = get_active_task(root)

    update_workstream(
        root,
        task=task.get("task", "Unknown"),
        mode=task.get("mode", "Unknown"),
        spec_path=task.get("spec", ""),
        phase=args.phase or "In Progress",
        summary=args.summary,
        next_step=args.next_step,
    )

    if args.decisions:
        append_decision(root, f"## Session Update\n{args.decisions}")
    if args.risks:
        append_risk(root, f"## Session Risk\n{args.risks}")

    print(f"\n  Session refreshed.")
    print(f"  Summary   : {args.summary}")
    print(f"  Next step : {args.next_step}")
    if args.phase:
        print(f"  Phase     : {args.phase}")
    print()


def cmd_status(args):
    """Show current project status."""
    root = get_root(args)
    task = get_active_task(root)
    analysis = analyze_repo(root)

    print(f"\n{'='*60}")
    print(f"  AIOS STATUS")
    print(f"{'='*60}")
    print(f"  Task    : {task.get('task') or 'None'}")
    print(f"  Mode    : {task.get('mode') or '-'}")
    print(f"  Phase   : {task.get('phase') or '-'}")
    print(f"  Stack   : {', '.join(analysis['stack']) or 'unknown'}")
    print(f"  Files   : {analysis['total_files']}")
    print(f"  Modules : {len(analysis['modules'])}")
    print(f"  Hotspots: {len(analysis['hotspots'])}")

    # Monorepo
    if is_monorepo(root):
        services = detect_services(root)
        active = detect_active_service(root)
        print(f"  Monorepo: YES ({len(services)} services)")
        for s in services[:8]:
            marker = " <-- active" if active and s["name"] == active["name"] else ""
            print(f"    {s['name']:25} [{s['type']}]{marker}")
    else:
        print(f"  Monorepo: no")

    # Specs
    specs_dir = root / "specs"
    if specs_dir.exists():
        specs = [d.name for d in specs_dir.iterdir() if d.is_dir()]
        print(f"  Specs   : {len(specs)}")
        for s in specs[-5:]:
            print(f"    - {s}")

    print(f"{'='*60}\n")


def cmd_analyze(args):
    """Analyze repository architecture + run stack checks."""
    root = get_root(args)
    analysis = analyze_repo(root)

    print(f"\n{'='*60}")
    print(f"  REPO ANALYSIS")
    print(f"{'='*60}")
    print(f"  Files    : {analysis['total_files']}")
    print(f"  Stack    : {', '.join(analysis['stack'])}")
    print(f"\n  Modules:")
    for mod, count in list(analysis["modules"].items())[:15]:
        print(f"    {mod:30} {count} files")
    if analysis["hotspots"]:
        print(f"\n  Hotspots (large files):")
        for h in analysis["hotspots"][:10]:
            print(f"    {h['file']:50} {h['size_kb']}KB")

    # Run stack checks
    stacks_detected = detect_relevant_stacks(root)
    if stacks_detected:
        print(f"\n  Stacks detected: {', '.join(stacks_detected)}")
        all_checks = run_all_relevant_checks(root)
        for stack_id, checks in all_checks.items():
            print(f"\n  [{stack_id.upper()}]")
            for c in checks:
                icon = {"pass": "OK", "warn": "!!", "fail": "XX", "info": "--"}[c["status"]]
                detail = f" -- {c.get('detail', '')}" if c.get("detail") else ""
                print(f"    [{icon}] {c['check']}{detail}")

    print(f"\n{'='*60}\n")


def cmd_module(args):
    """List or run stack modules."""
    root = get_root(args)

    if args.action == "list":
        stacks = list_stacks()
        detected = detect_relevant_stacks(root)
        print(f"\n{'='*60}")
        print(f"  AVAILABLE STACKS")
        print(f"{'='*60}")
        for s in stacks:
            active = "ACTIVE" if s["id"] in detected else ""
            print(f"  {s['id']:20} {s['name']:30} {active}")
        print(f"\n  Detected for this project: {', '.join(detected) or 'none'}")
        print(f"{'='*60}\n")

    elif args.action == "check":
        stack_id = args.stack
        if not stack_id:
            # Run all relevant
            all_checks = run_all_relevant_checks(root)
            for sid, checks in all_checks.items():
                print(f"\n  [{sid.upper()}]")
                for c in checks:
                    icon = {"pass": "OK", "warn": "!!", "fail": "XX", "info": "--"}[c["status"]]
                    detail = f" -- {c.get('detail', '')}" if c.get("detail") else ""
                    print(f"    [{icon}] {c['check']}{detail}")
        else:
            checks = run_stack_checks(stack_id, root)
            print(f"\n  [{stack_id.upper()} CHECKS]")
            for c in checks:
                icon = {"pass": "OK", "warn": "!!", "fail": "XX", "info": "--"}[c["status"]]
                detail = f" -- {c.get('detail', '')}" if c.get("detail") else ""
                print(f"    [{icon}] {c['check']}{detail}")
        print()


def cmd_release(args):
    """Check release readiness."""
    root = get_root(args)
    result = check_release_readiness(root)

    print(f"\n{'='*60}")
    print(f"  RELEASE GATE")
    print(f"{'='*60}")

    for c in result["checks"]:
        icon = {"pass": "OK", "warn": "!!", "fail": "XX"}[c["status"]]
        detail = f" -- {c.get('detail', '')}" if c.get("detail") else ""
        print(f"  [{icon}] {c['check']}{detail}")

    print(f"\n  Result: {result['passed']} passed, {result['warned']} warnings, {result['failed']} failed")
    print(f"  Ready for release: {'YES' if result['ready'] else 'NO'}")
    print(f"{'='*60}\n")


def cmd_doctor(args):
    """Diagnose AIOS health."""
    root = get_root(args)
    issues = []

    # Check structure
    for d in ["ai-system", "ai-memory", "specs"]:
        if not (root / d).exists():
            issues.append(f"Missing /{d} directory")

    # Check memory files
    for f in ["product_context.md", "tech_context.md", "architecture_context.md", "active_workstream.md"]:
        path = root / "ai-memory" / f
        if not path.exists():
            issues.append(f"Missing ai-memory/{f}")
        elif path.stat().st_size < 50:
            issues.append(f"ai-memory/{f} is empty (needs content)")

    # Check ai-system prompts
    for f in ["00_master_rules.md", "01_router.md", "02_session_boot.md"]:
        if not (root / "ai-system" / f).exists():
            issues.append(f"Missing ai-system/{f}")

    print(f"\n{'='*60}")
    print(f"  AIOS DOCTOR")
    print(f"{'='*60}")

    if issues:
        for i in issues:
            print(f"  [!!] {i}")
        print(f"\n  {len(issues)} issues found. Run: aios init")
    else:
        print(f"  All checks passed. AIOS is healthy.")

    print(f"{'='*60}\n")


def cmd_handoff(args):
    """Generate handoff document."""
    root = get_root(args)
    task = get_active_task(root)
    memory = read_memory(root)

    print(f"\n{'='*60}")
    print(f"  HANDOFF DOCUMENT")
    print(f"{'='*60}")
    print(f"\n  Task: {task.get('task', 'None')}")
    print(f"  Mode: {task.get('mode', '-')}")
    print(f"  Phase: {task.get('phase', '-')}")
    print(f"  Spec: {task.get('spec', '-')}")

    # Summary from workstream
    ws = memory.get("active_workstream.md", "")
    for line in ws.splitlines():
        if line.strip().startswith("## Session Summary"):
            idx = ws.splitlines().index(line)
            if idx + 1 < len(ws.splitlines()):
                print(f"\n  Summary: {ws.splitlines()[idx + 1].strip()}")

    # Decisions
    decs = memory.get("recent_decisions.md", "")
    dec_headers = [l for l in decs.splitlines() if l.startswith("## ")]
    if dec_headers:
        print(f"\n  Decisions ({len(dec_headers)}):")
        for d in dec_headers[-5:]:
            print(f"    {d}")

    # Risks
    risks = memory.get("known_risks.md", "")
    risk_lines = [l for l in risks.splitlines() if l.strip() and not l.startswith("#")]
    if risk_lines:
        print(f"\n  Open Risks:")
        for r in risk_lines[:5]:
            print(f"    {r.strip()}")

    print(f"\n{'='*60}\n")


def cmd_onboard(args):
    """Run onboarding wizard for new project."""
    root = get_root(args)
    report = run_onboard(root)

    print(f"\n{'='*60}")
    print(f"  AIOS ONBOARD")
    print(f"{'='*60}")
    for step in report["steps"]:
        print(f"  [OK] {step}")
    if report["warnings"]:
        print(f"\n  Warnings:")
        for w in report["warnings"]:
            print(f"  [!!] {w}")
    print(f"\n  Next steps:")
    for ns in report["next_steps"]:
        print(f"    {ns}")
    print(f"{'='*60}\n")


def cmd_guide(args):
    """Show troubleshooting guide."""
    print(get_guide(args.topic if hasattr(args, 'topic') else None))


def cmd_hook(args):
    """Manage git hooks."""
    root = get_root(args)
    if args.action == "list":
        hooks = list_hooks(root)
        print(f"\n{'='*60}")
        print(f"  HOOKS")
        print(f"{'='*60}")
        for h in hooks:
            status = "INSTALLED" if h["installed"] else "available"
            print(f"  {h['name']:25} [{status:10}] {h['description']}")
        print(f"{'='*60}\n")
    elif args.action == "install":
        if not args.name:
            print("  Usage: aios hook install --name pre-commit")
            return
        ok = install_git_hook(root, args.name, args.stack or "python")
        print(f"  Hook '{args.name}' {'installed' if ok else 'FAILED'}")


def cmd_mcp(args):
    """Generate MCP config for Kiro."""
    root = get_root(args)
    if args.action == "list":
        servers = list_available_servers()
        print(f"\n  Available MCP Servers:")
        for s in servers:
            default = " (default)" if s["default"] else ""
            print(f"    {s['name']:20} [{s['command']}]{default}")
        print()
    elif args.action == "init":
        extra = args.servers.split(",") if args.servers else []
        path = write_mcp_config(root, extra)
        print(f"  MCP config created: {path}")


def cmd_diff(args):
    """Show incremental changes since last analysis."""
    root = get_root(args)
    from aios.core.incremental import incremental_analyze
    result = incremental_analyze(root)

    print(f"\n{'='*60}")
    print(f"  AIOS DIFF (since {result['since']})")
    print(f"{'='*60}")
    print(f"  Changed files: {result['total_changed']}")
    for cat, files in result["categories"].items():
        print(f"\n  [{cat}] ({len(files)})")
        for f in files[:10]:
            print(f"    {f}")
        if len(files) > 10:
            print(f"    ... +{len(files) - 10} more")
    print(f"{'='*60}\n")


def cmd_impact(args):
    """Analyze impact of changing a file."""
    root = get_root(args)
    from aios.core.dependency_graph import build_dependency_graph, find_impact

    if args.file:
        affected = find_impact(root, args.file)
        print(f"\n{'='*60}")
        print(f"  IMPACT ANALYSIS: {args.file}")
        print(f"{'='*60}")
        print(f"  Files affected: {len(affected)}")
        for f in affected[:20]:
            print(f"    {f}")
        print(f"{'='*60}\n")
    else:
        graph = build_dependency_graph(root)
        print(f"\n{'='*60}")
        print(f"  DEPENDENCY GRAPH")
        print(f"{'='*60}")
        print(f"  Files analyzed: {graph['total_files']}")
        print(f"  Dependencies: {graph['total_edges']}")
        if graph["critical_modules"]:
            print(f"\n  Critical modules (most depended on):")
            for m in graph["critical_modules"][:10]:
                print(f"    {m['module']:40} ({m['depended_by']} dependents)")
        if graph["complex_files"]:
            print(f"\n  Complex files (most dependencies):")
            for f in graph["complex_files"][:10]:
                print(f"    {f['file']:50} ({f['dependencies']} deps)")
        print(f"{'='*60}\n")


def cmd_test(args):
    """Smart test runner — finds and runs affected tests."""
    root = get_root(args)
    if args.run:
        result = run_tests(root)
        print(f"\n{'='*60}")
        print(f"  TEST RESULTS")
        print(f"{'='*60}")
        print(f"  Framework: {result['framework']}")
        print(f"  Affected: {len(result.get('affected_tests', []))}")
        print(f"  Passed: {'YES' if result['passed'] else 'NO'}")
        if result.get('stdout'):
            print(f"\n  Output:\n{result['stdout'][-300:]}")
        print(f"{'='*60}\n")
    else:
        info = find_affected_tests(root)
        print(f"\n{'='*60}")
        print(f"  AFFECTED TESTS")
        print(f"{'='*60}")
        print(f"  Changed files: {info['changed_files']}")
        print(f"  Framework: {info['framework']}")
        print(f"  Affected tests ({len(info['affected_tests'])}):")
        for t in info["affected_tests"][:15]:
            print(f"    {t}")
        print(f"\n  Command: {info['command']}")
        print(f"  Run with: aios test --run")
        print(f"{'='*60}\n")


def cmd_progress(args):
    """Track migration/task progress across specs."""
    root = get_root(args)
    data = track_progress(root)

    print(f"\n{'='*60}")
    print(f"  PROGRESS TRACKER")
    print(f"{'='*60}")
    print(f"  Overall: {data['overall']}% ({data['completed_tasks']}/{data['total_tasks']} tasks)")

    for spec in data["specs"]:
        bar_len = 20
        filled = int(bar_len * spec["completion"] / 100)
        bar = "#" * filled + "-" * (bar_len - filled)
        print(f"\n  [{spec['mode']:8}] {spec['name'][:40]}")
        print(f"    {bar} {spec['completion']}% ({spec['tasks_completed']}/{spec['tasks_total']} tasks)")
        docs = []
        if spec["has_design"]: docs.append("design")
        if spec["has_validation"]: docs.append("validation")
        if spec["has_rollback"]: docs.append("rollback")
        if docs:
            print(f"    Docs: {', '.join(docs)}")
    print(f"{'='*60}\n")


def cmd_watch(args):
    """Watch for file changes and run analysis."""
    root = get_root(args)
    from aios.core.watcher import watch_changes

    def on_change(r, diff):
        print(f"\n  [CHANGE DETECTED] {len(diff.splitlines())} files modified")
        from aios.core.incremental import incremental_analyze
        result = incremental_analyze(r)
        print(f"  Changed: {result['total_changed']} files")
        for cat, files in result["categories"].items():
            print(f"    [{cat}] {len(files)}")

    print(f"  Watching {root} for changes (Ctrl+C to stop)...")
    watch_changes(root, on_change, interval=int(args.interval or 5))


def cmd_cache(args):
    """Manage analysis cache."""
    root = get_root(args)
    if args.action == "clear":
        invalidate_cache(root)
        print("  Cache cleared.")
    elif args.action == "status":
        cache_dir = root / ".aios" / "cache"
        if cache_dir.exists():
            files = list(cache_dir.glob("*.json"))
            print(f"  Cache: {len(files)} entries in {cache_dir}")
        else:
            print("  No cache.")


# ═══════════════════════════════════════
# MAIN
# ═══════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(prog="aios", description="AIOS - AI Engineering Operating System")
    sub = parser.add_subparsers(dest="command")

    # init
    p = sub.add_parser("init", help="Initialize AIOS in a project")
    p.add_argument("--root", default=".")

    # task
    p = sub.add_parser("task", help="Create a new task")
    p.add_argument("--task", required=True, help="Task description")
    p.add_argument("--mode", choices=["BUGFIX", "FEATURE", "MIGRATION", "LEGACY_MODERNIZATION"])
    p.add_argument("--context", help="Extra context")
    p.add_argument("--root", default=".")

    # boot
    p = sub.add_parser("boot", help="Start session")
    p.add_argument("--root", default=".")

    # refresh
    p = sub.add_parser("refresh", help="End session")
    p.add_argument("--summary", required=True)
    p.add_argument("--next-step", required=True)
    p.add_argument("--phase", help="Current phase")
    p.add_argument("--decisions", help="Decisions made")
    p.add_argument("--risks", help="New risks")
    p.add_argument("--root", default=".")

    # status
    p = sub.add_parser("status", help="Show project status")
    p.add_argument("--root", default=".")

    # analyze
    p = sub.add_parser("analyze", help="Analyze repo architecture")
    p.add_argument("--root", default=".")

    # release
    p = sub.add_parser("release", help="Check release readiness")
    p.add_argument("--root", default=".")

    # doctor
    p = sub.add_parser("doctor", help="Diagnose AIOS health")
    p.add_argument("--root", default=".")

    # module
    p = sub.add_parser("module", help="Stack modules")
    p.add_argument("action", choices=["list", "check"], help="list or check")
    p.add_argument("--stack", help="Specific stack to check")
    p.add_argument("--root", default=".")

    # handoff
    p = sub.add_parser("handoff", help="Generate handoff document")
    p.add_argument("--root", default=".")

    # onboard
    p = sub.add_parser("onboard", help="Onboarding wizard for new projects")
    p.add_argument("--root", default=".")

    # guide
    p = sub.add_parser("guide", help="Troubleshooting guide and FAQ")
    p.add_argument("--topic", choices=get_topics(), help="Specific topic")

    # hook
    p = sub.add_parser("hook", help="Manage git hooks")
    p.add_argument("action", choices=["list", "install"])
    p.add_argument("--name", help="Hook name to install")
    p.add_argument("--stack", help="Stack for hook templates (python/react)")
    p.add_argument("--root", default=".")

    # mcp
    p = sub.add_parser("mcp", help="MCP server configuration")
    p.add_argument("action", choices=["list", "init"])
    p.add_argument("--servers", help="Extra servers (comma-separated)")
    p.add_argument("--root", default=".")

    # diff
    p = sub.add_parser("diff", help="Show incremental changes")
    p.add_argument("--root", default=".")

    # impact
    p = sub.add_parser("impact", help="Dependency graph + impact analysis")
    p.add_argument("--file", help="File to analyze impact for")
    p.add_argument("--root", default=".")

    # config
    p = sub.add_parser("config", help="Project configuration")
    p.add_argument("action", choices=["init", "show", "set"], help="init, show, or set")
    p.add_argument("--project-name", help="Project name")
    p.add_argument("--policy", choices=["default", "enterprise"], help="Policy tier")
    p.add_argument("--key", help="Config key to set")
    p.add_argument("--value", help="Config value to set")
    p.add_argument("--root", default=".")

    # test
    p = sub.add_parser("test", help="Smart test runner")
    p.add_argument("--run", action="store_true", help="Actually run the tests")
    p.add_argument("--root", default=".")

    # progress
    p = sub.add_parser("progress", help="Track migration/task progress")
    p.add_argument("--root", default=".")

    # watch
    p = sub.add_parser("watch", help="Watch for file changes")
    p.add_argument("--interval", default="5", help="Check interval in seconds")
    p.add_argument("--root", default=".")

    # cache
    p = sub.add_parser("cache", help="Manage analysis cache")
    p.add_argument("action", choices=["clear", "status"])
    p.add_argument("--root", default=".")

    # version
    p = sub.add_parser("version", help="Show AIOS version")

    args = parser.parse_args()

    commands = {
        "init": cmd_init, "task": cmd_task, "boot": cmd_boot,
        "refresh": cmd_refresh, "status": cmd_status, "analyze": cmd_analyze,
        "release": cmd_release, "doctor": cmd_doctor, "handoff": cmd_handoff,
        "module": cmd_module, "config": cmd_config, "version": cmd_version,
        "diff": cmd_diff, "impact": cmd_impact,
        "onboard": cmd_onboard, "guide": cmd_guide, "hook": cmd_hook, "mcp": cmd_mcp,
        "test": cmd_test, "progress": cmd_progress, "watch": cmd_watch, "cache": cmd_cache,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


def cmd_config(args):
    """Manage project configuration."""
    root = get_root(args)

    if args.action == "init":
        config = init_config(root, project_name=args.project_name or "", policy=args.policy or "default")
        print(f"\n  Config initialized: {root / '.aios' / 'config.json'}")
        print(f"  Project: {config['project_name']}")
        print(f"  Policy: {config['policy']}\n")

    elif args.action == "show":
        config = load_config(root)
        print(f"\n{'='*60}")
        print(f"  AIOS CONFIG")
        print(f"{'='*60}")
        for k, v in config.items():
            print(f"  {k:25} : {v}")
        print(f"{'='*60}\n")

    elif args.action == "set":
        if not args.key or args.value is None:
            print("  Usage: aios config set --key <key> --value <value>")
            return
        config = load_config(root)
        # Parse value
        val = args.value
        if val.lower() == "true": val = True
        elif val.lower() == "false": val = False
        elif val.startswith("["): val = json.loads(val)
        config[args.key] = val
        save_config(root, config)
        print(f"  Set {args.key} = {val}")


def cmd_version(args):
    """Show AIOS version."""
    from aios import __version__
    print(f"  AIOS v{__version__}")


if __name__ == "__main__":
    main()
