#!/usr/bin/env python3
"""AIOS CLI — AI Engineering Operating System v1.5.0"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

# v1.5.0 · Force UTF-8 on Windows console (fixes ·, →, ⭐ rendering as ?)
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, Exception):
        # Older Python or non-reconfigurable streams · fallback silent
        pass

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
from aios.core.arena_runner import (
    run_arena,
    list_targets as arena_list_targets,
    write_arena_summary_to_memory,
    read_last_arena_run,
)
from aios.core.engagement_scaffold import run_scaffold as run_engagement_scaffold
from aios.core.report_aggregator import build_report, write_report
from aios.core.compliance import (
    render_compliance_report,
    render_compliance_report_html,
    render_compliance_report_pdf,
)
from aios.core.security_gate import (
    scan_directory as _scan_directory,
    scan_files as _scan_files,
)
from aios.core.suppressions import (
    Suppression, add_suppression, load_suppressions, list_expired,
)
from aios.core.trending import build_trending, render_trending_markdown
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
from aios.core.refine import analyze_spec, refine_all_specs
from aios.core.kiro_bridge import sync_to_kiro, search_codebase
from aios.core.changelog import save_changelog, clear_changelog, get_changelog_size, generate_changelog


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

    # Last Arena run · integracion bidireccional
    last = read_last_arena_run(root)
    if last:
        print(f"  Last arena: {last['target']} → {last['verdict']} ({last['timestamp']})")

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

    icons = {"pass": "OK", "warn": "!!", "fail": "XX", "skip": "--"}
    for c in result["checks"]:
        icon = icons.get(c["status"], "??")
        detail = f" -- {c.get('detail', '')}" if c.get("detail") else ""
        print(f"  [{icon}] {c['check']}{detail}")

    # Security gate breakdown · solo si hay findings
    sec = result.get("security", {})
    summary = sec.get("findings_summary", {})
    top = sec.get("top_findings", [])
    if summary or top:
        print(f"\n  Security findings breakdown:")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            n = summary.get(sev, 0)
            if n:
                print(f"    {sev:<8} {n}")
        if top:
            print(f"\n  Top findings:")
            for f in top:
                print(f"    [{f['severity']:<8}] {f['cwe']} · {f['rule_id']} · {f['file']}:{f['line']}")

    skipped = result.get("skipped", 0)
    summary_line = (
        f"  Result: {result['passed']} passed, {result['warned']} warnings, "
        f"{result['failed']} failed"
    )
    if skipped:
        summary_line += f", {skipped} skipped"
    print(f"\n{summary_line}")
    print(f"  Ready for release: {'YES' if result['ready'] else 'NO'}")
    print(f"{'='*60}\n")

    # Notifica Slack si se bloqueo (opt-in via config.notifications)
    if not result["ready"]:
        try:
            from aios.core.notifications import notify_release_blocked
            notif = notify_release_blocked(
                root,
                result.get("security", {}).get("findings_summary", {}),
                result.get("security", {}).get("top_findings", []),
                project_name=root.name,
            )
            if notif and notif.sent:
                print(f"[notify] Slack alert enviado · {notif.detail}")
        except Exception:  # noqa: BLE001
            pass


def cmd_arena(args):
    """Ejecuta Arena self-play contra un TUT bajo demanda.

    NO se integra en `aios release` (demasiado lento) · este comando
    es para correrlo manual y ver verdict + timeline.
    """
    if args.list:
        targets = arena_list_targets()
        if not targets:
            print("arena CLI no disponible o sin TUTs. Ver HANDOFF.md.")
            return
        print("TUTs disponibles:")
        for t in targets:
            print(f"  · {t}")
        return

    if not args.target:
        print("Uso: aios arena --target <tut-id> [--target-url URL] "
              "[--max-rounds N] [--list]")
        return

    print(f"\n{'='*60}")
    print(f"  ARENA SELF-PLAY")
    print(f"{'='*60}")
    print(f"  target={args.target} · max_rounds={args.max_rounds}" +
          (f" · target-url={args.target_url}" if args.target_url else ""))
    print(f"  (invocando arena CLI · esto tarda minutos)")
    print()

    result = run_arena(
        target=args.target,
        target_url=args.target_url,
        max_rounds=args.max_rounds,
        timeout_seconds=args.timeout,
    )

    if not result.ok:
        print(f"  [XX] {result.detail}")
        return

    icon = {"MYTHOS_WINS": "OK", "NEMESIS_WINS": "XX",
            "STALEMATE": "!!", "DRAW": "--", "USER_STOPPED": "--"}.get(
        result.verdict or "", "??"
    )
    print(f"  [{icon}] Verdict: {result.verdict}")
    print(f"       Rounds completed : {result.rounds_completed}")
    print(f"       Mythos win streak: {result.mythos_win_streak}")
    print(f"       Stalemate counter: {result.stalemate_counter}")
    print(f"       Elapsed          : {result.elapsed_seconds:.1f}s")
    if result.timeline_path:
        print(f"       Timeline         : {result.timeline_path}")

    # Integracion bidireccional · persiste el resumen en ai-memory/
    root = get_root(args)
    written = write_arena_summary_to_memory(
        root, result, args.target, target_url=args.target_url,
    )
    if written:
        print(f"       Memory           : {written.relative_to(root)}")
    print(f"{'='*60}\n")


def cmd_report(args):
    """Agrega release gate + last arena + SARIF findings + engagements
    en un markdown consolidado bajo `reports/aios_report_<ts>.md`."""
    root = get_root(args)
    report = build_report(root)
    dest = write_report(root, report)

    print(f"\n{'='*60}")
    print(f"  AIOS AGGREGATE REPORT")
    print(f"{'='*60}")
    print(f"  Generated : {report.generated_at}")
    print(f"  Sections  : {len(report.sections)}")
    for s in report.sections:
        icon = {"pass": "OK", "warn": "!!", "fail": "XX", "info": "--"}.get(s.status, "??")
        print(f"  [{icon}] {s.title}")
    print(f"\n  Written   : {dest.relative_to(root)}")
    print(f"{'='*60}\n")


def cmd_security_scan_staged(args):
    """Scan solo los archivos provistos (stdin o --files). Exit 1 si
    hay CRITICAL findings · usado por el pre-commit hook."""
    root = get_root(args)

    if args.stdin:
        files = [line.strip() for line in sys.stdin if line.strip()]
    elif args.files:
        files = args.files
    else:
        print("[XX] pasa --stdin o --files <path1> <path2>")
        sys.exit(2)

    if not files:
        print("[AIOS/scan-staged] No files to scan")
        return

    # v2.1.1 · BUG-004 · advertir sobre scope para evitar confusion con
    # 'aios release' (que escanea workspace completo)
    try:
        import subprocess as _sp
        total_files_proc = _sp.run(
            ["git", "ls-files"], capture_output=True, text=True,
            cwd=str(root), check=False, timeout=5,
        )
        if total_files_proc.returncode == 0:
            total_tracked = len([
                l for l in total_files_proc.stdout.splitlines() if l.strip()
            ])
            if total_tracked > len(files):
                print(
                    f"[AIOS/scan-staged] SCOPE · {len(files)} staged files "
                    f"de {total_tracked} tracked en repo · para scan "
                    f"completo del workspace usa `aios release`"
                )
    except Exception:  # noqa: BLE001
        pass

    findings = _scan_files(root, files)
    critical = [f for f in findings if f.severity == "CRITICAL"]
    high = [f for f in findings if f.severity == "HIGH"]

    print(f"[AIOS/scan-staged] {len(files)} files · "
          f"{len(findings)} findings ({len(critical)} CRITICAL, {len(high)} HIGH)")
    for f in critical[:10]:
        print(f"  [CRITICAL] {f.cwe} · {f.rule_id} · {f.file}:{f.line}")
    for f in high[:10]:
        print(f"  [HIGH]     {f.cwe} · {f.rule_id} · {f.file}:{f.line}")

    if critical:
        sys.exit(1)


def cmd_trending(args):
    """Chart ASCII/markdown de findings historicos."""
    root = get_root(args)
    data = build_trending(root)

    if args.json:
        import json as _json
        print(_json.dumps(data, indent=2, default=str))
        return

    md = render_trending_markdown(data)
    if args.output:
        dest = Path(args.output)
        if not dest.is_absolute():
            dest = root / dest
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(md, encoding="utf-8")
        print(f"Written: {dest.relative_to(root) if dest.is_relative_to(root) else dest}")
    else:
        print(md)


def cmd_suppress(args):
    """Crea/lista/expira suppressions (waivers) de findings."""
    root = get_root(args)
    print(f"\n{'='*60}")
    print(f"  SUPPRESSIONS")
    print(f"{'='*60}")

    if args.action == "list":
        sups = load_suppressions(root)
        if not sups:
            print("  (sin suppressions)")
        else:
            for i, s in enumerate(sups, 1):
                expired = " · EXPIRED" if s.is_expired() else ""
                print(
                    f"  [{i}] {s.rule_id} · {s.file}:{s.line}{expired}\n"
                    f"      reason:   {s.reason[:70]}\n"
                    f"      approver: {s.approver} ({s.approved_at})"
                )
        print(f"{'='*60}\n")
        return

    if args.action == "check-expired":
        expired = list_expired(load_suppressions(root))
        if not expired:
            print("  (todas vigentes)")
        else:
            print(f"  [!!] {len(expired)} waivers expirados:")
            for s in expired:
                print(f"      {s.rule_id} · {s.file}:{s.line} · expiro {s.expires_at}")
        print(f"{'='*60}\n")
        return

    if args.action == "add":
        if not (args.rule_id and args.file and args.reason and args.approver):
            print("  [XX] add requiere --rule-id --file --reason --approver")
            print(f"{'='*60}\n")
            return
        from datetime import date
        sup = Suppression(
            rule_id=args.rule_id,
            file=args.file,
            line=args.line or 0,
            cwe=args.cwe or "",
            reason=args.reason,
            approver=args.approver,
            approved_at=args.approved_at or str(date.today()),
            expires_at=args.expires_at or "",
        )
        dest = add_suppression(root, sup)
        print(f"  [OK] suppression agregada a {dest.name}")
        print(f"       {sup.rule_id} · {sup.file}:{sup.line}")
        print(f"{'='*60}\n")
        return


def cmd_compliance_report(args):
    """Genera reporte de compliance · findings agrupados por marco
    regulatorio (LFPDPPP · PCI-DSS · SOX · CFF art. 30 · OWASP)."""
    root = get_root(args)
    print(f"\n{'='*60}")
    print(f"  COMPLIANCE REPORT")
    print(f"{'='*60}")

    findings = _scan_directory(root)
    if not findings:
        print("  [OK] 0 findings · sin mapeos a marcos regulatorios")
        print(f"{'='*60}\n")
        return

    project_name = root.name
    fmt = (args.format or "md").lower()

    if fmt == "html":
        out = render_compliance_report_html(findings, project_name)
        ext = ".html"
    elif fmt == "pdf":
        if not args.output:
            print("  [!!] --format pdf requires --output <file.pdf>")
            print(f"{'='*60}\n")
            return
        dest = Path(args.output)
        if not dest.is_absolute():
            dest = root / dest
        dest.parent.mkdir(parents=True, exist_ok=True)
        ok, msg = render_compliance_report_pdf(findings, dest, project_name)
        icon = "OK" if ok else "!!"
        print(f"  [{icon}] {msg}")
        print(f"{'='*60}\n")
        return
    else:
        out = render_compliance_report(findings, project_name)
        ext = ".md"

    if args.output:
        dest = Path(args.output)
        if not dest.is_absolute():
            dest = root / dest
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(out, encoding="utf-8")
        rel = dest.relative_to(root) if dest.is_relative_to(root) else dest
        print(f"  Written: {rel}")
    else:
        print(out)

    print(f"{'='*60}\n")


def cmd_engagement(args):
    """Invoca el scaffolder de Nemesis engagements (AMX Revenue
    Accounting scope).

    Requiere `nemesis-engagements/_catalog/scaffold.py` reachable ·
    configurar `engagement.scaffold_script` en aios-config.json o
    copiar el script a location por default.
    """
    root = get_root(args)

    scaffold_args: list[str] = []
    if args.list:
        scaffold_args.append("--list")
    elif args.all:
        scaffold_args.append("--all")
    elif args.app:
        scaffold_args.extend(["--app", args.app])
    else:
        print("Uso: aios engagement {--list | --all | --app <app-id>} "
              "[--quarter 2026-Q2] [--force] [--dry-run]")
        return

    if args.quarter:
        scaffold_args.extend(["--quarter", args.quarter])
    if args.force:
        scaffold_args.append("--force")
    if args.dry_run:
        scaffold_args.append("--dry-run")

    result = run_engagement_scaffold(root, scaffold_args, timeout=args.timeout)

    print(f"\n{'='*60}")
    print(f"  ENGAGEMENT SCAFFOLD")
    print(f"{'='*60}")
    if not result.ok:
        print(f"  [XX] exit={result.exit_code}")
        if result.stderr:
            print(f"       stderr: {result.stderr.strip()[:400]}")
        if result.stdout:
            print(f"       stdout: {result.stdout.strip()[:400]}")
    else:
        print(result.stdout.rstrip())
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


def cmd_scaffold_deploy_ready(args):
    """Auto-detect app + scaffold deploy-ready package (docs · IaC · CI/CD · tests · runbook)."""
    from aios.core.deploy_ready import detect_profile, scaffold, generate_mythos_tut

    app_path = Path(args.app_path).resolve()
    overwrite = getattr(args, "overwrite", False)
    register_mythos = not getattr(args, "no_mythos", False)

    print(f"\n{'='*60}")
    print(f"  AIOS · SCAFFOLD DEPLOY-READY")
    print(f"{'='*60}")
    print(f"  App path · {app_path}")

    profile = detect_profile(app_path)

    # CLI override for primary stack (use case: target stack differs from current code)
    stack_override = getattr(args, "primary_stack", None)
    if stack_override and stack_override != profile.primary_stack:
        print(f"\n  [!] Stack override · auto-detected '{profile.primary_stack}' → forcing '{stack_override}'")
        profile.primary_stack = stack_override
        if stack_override not in profile.detected_stacks:
            profile.detected_stacks.append(stack_override)
        profile.notes.append(f"primary_stack manually overridden via CLI · original detection: auto")

    output_dir_arg = getattr(args, "output_dir", None)
    output_dir = Path(output_dir_arg) if output_dir_arg else None

    print(f"\n  Profile detectado:")
    print(f"    app_id            · {profile.app_id}")
    print(f"    app_name          · {profile.app_name}")
    print(f"    primary_stack     · {profile.primary_stack}")
    print(f"    detected_stacks   · {', '.join(profile.detected_stacks) or '(none)'}")
    print(f"    tier_proposed     · {profile.tier_proposed}")
    print(f"    tier_rationale    · {profile.tier_rationale}")
    print(f"    criticality       · {profile.criticality}")
    print(f"    workload          · {'CronJob (batch)' if profile.is_batch else 'Deployment (service)'}")
    print(f"    vulns_known       · {len(profile.vulns_known)}  ({sum(1 for v in profile.vulns_known if v.severity == 'CRITICAL')} CRITICAL · {sum(1 for v in profile.vulns_known if v.severity == 'HIGH')} HIGH)")
    print(f"    integrations      · {', '.join(profile.integrations) or '(none)'}")
    print(f"    compliance        · {', '.join(profile.compliance) or '(none)'}")
    print(f"    has_discovery     · {profile.has_discovery}")
    print(f"    has_code          · {profile.has_code}")
    if profile.notes:
        print(f"\n  Notes:")
        for n in profile.notes:
            print(f"    [!] {n}")

    print(f"\n  Scaffolding deploy-ready/ ...")
    report = scaffold(profile, output_dir=output_dir, overwrite=overwrite)
    print(f"    files_created  · {len(report.files_created)}")
    print(f"    files_skipped  · {len(report.files_skipped)} (already exist · use --overwrite)")
    for w in report.warnings:
        print(f"    [!] {w}")

    if register_mythos:
        repo_root = Path(getattr(args, "root", None) or Path.cwd()).resolve()
        tut = generate_mythos_tut(profile, repo_root)
        if tut:
            print(f"\n  Mythos TUT registered · {tut}")
        else:
            print(f"\n  [!] Mythos TUT skipped · mythos/mythos-targets/ not found under {repo_root}")

    print(f"\n  Next steps:")
    print(f"    1. Review deploy-ready/ARCHITECT_PACKAGE_README.md")
    print(f"    2. Enrich ADR-001 and ADR-002 with app-specific decisions")
    print(f"    3. Complete C4 diagrams (drawio skeleton not generated · copy from similar app)")
    print(f"    4. Run Mythos scan · mythos scan {profile.app_id}-{profile.primary_stack}")
    print(f"    5. Escalate to Borde Arquitectura (Israel Miguel) for Gate 4 review")
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


def cmd_refine(args):
    """Analyze spec completeness and suggest improvements."""
    root = get_root(args)
    if args.spec:
        spec_dir = root / "specs" / args.spec
        result = analyze_spec(spec_dir)
        print(f"\n{'='*60}")
        print(f"  SPEC REFINEMENT: {result.get('spec', '?')}")
        print(f"{'='*60}")
        print(f"  Readiness: {result['average']}%")
        for name, score in result.get("scores", {}).items():
            bar = "#" * (score // 5) + "-" * (20 - score // 5)
            print(f"    {name:30} {bar} {score}%")
        if result.get("issues"):
            print(f"\n  Issues:")
            for i in result["issues"]:
                print(f"    [!!] {i['file']}: {i['issue']}")
        if result.get("suggestions"):
            print(f"\n  Suggestions:")
            for s in result["suggestions"]:
                print(f"    -> {s}")
        print(f"{'='*60}\n")
    else:
        results = refine_all_specs(root)
        print(f"\n{'='*60}")
        print(f"  SPEC REFINEMENT — ALL SPECS")
        print(f"{'='*60}")
        for r in results:
            bar = "#" * (r["average"] // 5) + "-" * (20 - r["average"] // 5)
            print(f"  {r['spec'][:40]:42} {bar} {r['average']}%")
        print(f"{'='*60}\n")


def cmd_sync(args):
    """Sync AIOS structure to Kiro IDE format."""
    root = get_root(args)
    result = sync_to_kiro(root)
    print(f"\n  Synced to Kiro:")
    print(f"    Steering:    {result['steering_files']} files -> {result['steering_path']}")
    print(f"    Specs:       {result['specs_count']} specs -> {result['specs_path']}")
    # v1.5.0 · per-app sync info
    if result.get('app_memory_files', 0) > 0:
        print(f"    App memory:  {result['app_memory_files']} files -> {result['app_memory_path']}")
    if result.get('app_agents_files', 0) > 0:
        print(f"    App agents:  {result['app_agents_files']} files -> {result['app_agents_path']}")
    print()


def cmd_search(args):
    """Search codebase for a query."""
    root = get_root(args)
    results = search_codebase(root, args.query)
    print(f"\n  Search: '{args.query}' ({len(results)} results)\n")
    for r in results:
        print(f"  {r['file']}:{r['line']}  {r['content']}")
    print()


def cmd_changelog(args):
    """Generate or view changelog."""
    root = get_root(args)
    commits = int(args.commits or 3)

    if args.action == "generate":
        path = save_changelog(root, commits)
        size = get_changelog_size(root)
        print(f"\n  Changelog saved: {path} ({size}KB)")
        print(f"  Covers last {commits} commits\n")

    elif args.action == "show":
        data = generate_changelog(root, commits)
        print(f"\n{'='*60}")
        print(f"  CHANGELOG (last {commits} commits)")
        print(f"{'='*60}")
        for e in data["entries"]:
            added = sum(1 for f in e["files"] if f["status"] == "A")
            modified = sum(1 for f in e["files"] if f["status"] == "M")
            print(f"\n  [{e['sha']}] {e['message']}")
            print(f"    {e['date']} | +{added} added, ~{modified} modified | {e['stat']}")
            for f in e["files"][:8]:
                icon = {"A": "+", "M": "~", "D": "-"}.get(f["status"], "?")
                print(f"      {icon} {f['file']}")
            if len(e["files"]) > 8:
                print(f"      ... +{len(e['files']) - 8} more")
        print(f"\n{'='*60}\n")


def cmd_clean(args):
    """Clean AIOS artifacts to free memory."""
    root = get_root(args)
    cleaned = []

    if args.target in ("all", "changelog"):
        if clear_changelog(root):
            cleaned.append("changelog")

    if args.target in ("all", "cache"):
        invalidate_cache(root)
        cleaned.append("cache")

    if args.target in ("all", "specs"):
        specs_dir = root / "specs"
        if specs_dir.exists():
            import shutil
            count = len(list(specs_dir.iterdir()))
            shutil.rmtree(specs_dir)
            specs_dir.mkdir()
            cleaned.append(f"specs ({count} removed)")

    if args.target in ("all", "memory"):
        # Reset memory files to defaults (keep structure)
        from aios.core.memory_engine import MEMORY_DEFAULTS
        for name, content in MEMORY_DEFAULTS.items():
            (root / "ai-memory" / name).write_text(content, encoding="utf-8")
        cleaned.append("memory (reset to defaults)")

    if cleaned:
        print(f"\n  Cleaned: {', '.join(cleaned)}\n")
    else:
        print(f"\n  Nothing to clean. Use: aios clean --target all/changelog/cache/specs/memory\n")


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

    # v1.7.3 · resume · retoma sesion desde checkpoint guardado
    p = sub.add_parser("resume",
                       help="Retoma la sesion desde el ultimo checkpoint "
                            "(BUG-003 · fix context-limit interruptions)")
    p.add_argument("--root", default=".")
    p.add_argument("--format", choices=["human", "json"], default="human",
                   help="Formato de salida")

    # v1.7.3 · checkpoint · emite/actualiza checkpoint manual
    p = sub.add_parser("checkpoint",
                       help="Escribe o muestra el checkpoint actual del "
                            "workstream · util despues de cada build-gate PASS")
    p.add_argument("--root", default=".")
    p.add_argument("--phase-completed", default="",
                   help="Ultima fase cerrada (ej. 'FASE 2')")
    p.add_argument("--phase-in-progress", default="",
                   help="Fase+step en curso (ej. 'FASE 3 · step 2/6')")
    p.add_argument("--next-action", default="",
                   help="Accion inmediata a retomar")
    p.add_argument("--last-commit", default="",
                   help="Hash del ultimo commit atomico")
    p.add_argument("--show", action="store_true",
                   help="Solo muestra el checkpoint actual · no escribe")

    # v1.9.0 · RFC-003 Nivel 2 · LLM classifier CLI
    p = sub.add_parser("classify",
                       help="Clasifica un finding usando ontology + LLM · "
                            "debug/preview sin correr scan completo")
    p.add_argument("--root", default=".")
    p.add_argument("--file", required=True, help="Archivo del finding")
    p.add_argument("--line", type=int, required=True, help="Linea del finding")
    p.add_argument("--rule-id", required=True, help="Rule ID del finding")
    p.add_argument("--severity", default="CRITICAL")
    p.add_argument("--snippet", default="",
                   help="Snippet del codigo · si omite, se extrae del archivo")
    p.add_argument("--provider", default="",
                   help="Override provider (mock|anthropic|openai|ollama)")
    p.add_argument("--no-llm", action="store_true",
                   help="Solo ontology (Nivel 1) · no invoca LLM")
    p.add_argument("--format", choices=["human", "json"], default="human")

    # v2.0.0 · RFC-003 Nivel 3 · Characterization tests CLI
    p = sub.add_parser("characterize",
                       help="Captura/verifica behavior fingerprint · "
                            "rollback-safe refactor validation")
    p.add_argument("--root", default=".")
    p.add_argument("action",
                   choices=["capture", "verify", "show", "diff"],
                   help="capture: snapshot pre-refactor · "
                        "verify: comparar post vs baseline · "
                        "show: mostrar fingerprint guardado · "
                        "diff: comparar 2 archivos directamente")
    p.add_argument("--file", required=True, help="Archivo target")
    p.add_argument("--vs", default="",
                   help="Para diff: segundo archivo a comparar")
    p.add_argument("--format", choices=["human", "json"], default="human")

    # v2.2.0 · RFC-004a + RFC-004b · Cross-Copy Drift Detector CLI
    p = sub.add_parser("drift",
                       help="Detecta divergencia cross-copy (source vs build vs prod) "
                            "+ credenciales byte-idénticas entre ambientes")
    p.add_argument("--source", required=True,
                   help="Primer directorio (ej. source tree)")
    p.add_argument("--compare", required=True,
                   help="Segundo directorio (ej. build output · prod deployed)")
    p.add_argument("--format", choices=["human", "json"], default="human")
    p.add_argument("--severity-min", default="INFO",
                   choices=["INFO", "MEDIUM", "HIGH", "CRITICAL"],
                   help="Filtra findings bajo este nivel")

    # v2.1.0 · RFC-003 Nivel 4 · Stakeholder-in-the-Loop CLI
    p = sub.add_parser("review",
                       help="Gestiona decisiones sobre findings que "
                            "requieren review humano (approve/reject/defer) · "
                            "audit trail en .aios/review-log.jsonl")
    p.add_argument("--root", default=".")
    p.add_argument("action",
                   choices=["list", "show", "approve", "reject", "defer", "generate"],
                   help="list: findings pendientes · show <id>: doc del finding · "
                        "approve/reject/defer: registrar decisión · "
                        "generate: emite review docs para findings pause actuales")
    p.add_argument("--id", default="", help="Finding ID (ej. FRK-a3f8e1b2)")
    p.add_argument("--reason", default="", help="Razón de la decisión (texto)")
    p.add_argument("--classification", default="",
                   choices=["", "bug", "business_rule", "migration_candidate", "unclear"],
                   help="Al approve: reclasificación final (opcional)")
    p.add_argument("--user", default="",
                   help="Usuario que decide (default: git user.email)")
    p.add_argument("--add-to-ontology", action="store_true",
                   help="Al approve: propone entry al ontology (merge manual)")
    p.add_argument("--pattern", default="",
                   help="Regex pattern para ontology proposed (override auto-extract)")
    p.add_argument("--format", choices=["human", "json"], default="human")

    # v2.3.0 · RFC-004c · Third-Party Exfil Heuristic
    p = sub.add_parser("exfil",
                       help="Detecta emails/URLs/hosts hacia dominios no "
                            "corporativos en configs + codigo (data exfil heuristic)")
    p.add_argument("--root", default=".",
                   help="Directorio a escanear (default: cwd)")
    p.add_argument("--corporate", default="",
                   help="CSV de dominios corporativos whitelisted "
                        "(default: aeromexico.com.mx,am.com.mx,aeromexicocargo.com)")
    p.add_argument("--severity-min", default="INFO",
                   choices=["INFO", "MEDIUM", "HIGH"],
                   help="Filtra findings bajo este nivel")
    p.add_argument("--format", choices=["human", "json"], default="human")

    # v2.8.0 · Dynamic analysis hooks (test stubs · Falco rules · OTel)
    p = sub.add_parser("dynamic-hooks",
                       help="Genera stubs de integration tests + reglas Falco + "
                            "sugerencias OpenTelemetry desde characterization y "
                            "findings · no corre nada · prepara artefactos CI/CD")
    p.add_argument("--root", default=".",
                   help="Directorio raiz (default cwd)")
    p.add_argument("--characterization-dir", default="",
                   help="Dir con .json fingerprints (default: .aios/characterization)")
    p.add_argument("--findings-file", default="",
                   help="JSON con findings para emitir reglas Falco por CWE")
    p.add_argument("--format", choices=["human", "json"], default="human")

    # v2.6.0 · Ensemble OSS scanner (Semgrep/Gitleaks/TruffleHog/Bandit/Checkov/Trivy)
    p = sub.add_parser("ensemble",
                       help="Corre herramientas OSS ortogonales (Semgrep · "
                            "Gitleaks · TruffleHog · Bandit · Checkov · Trivy) "
                            "y consolida findings para elevar recall")
    p.add_argument("--root", default=".",
                   help="Directorio a escanear (default: cwd)")
    p.add_argument("--tools", default="",
                   help="CSV de tools a correr (default: auto-detect)")
    p.add_argument("--timeout", type=int, default=600,
                   help="Timeout por tool en segundos (default 600)")
    p.add_argument("--severity-min", default="INFO",
                   choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   help="Filtra findings bajo este nivel")
    p.add_argument("--format", choices=["human", "json"], default="human")

    # v2.4.0 · RFC-004d · Runtime Data File Scanner
    p = sub.add_parser("runtime-data",
                       help="Escanea archivos runtime (HTML/TXT/logs/CSV/EML) "
                            "en busca de PII · PNRs · credit cards · JWTs · "
                            "credentials fuera del CWE scan estandar")
    p.add_argument("--root", default=".",
                   help="Directorio a escanear (default: cwd)")
    p.add_argument("--severity-min", default="INFO",
                   choices=["INFO", "MEDIUM", "HIGH"],
                   help="Filtra findings bajo este nivel")
    p.add_argument("--max-mb", type=int, default=4,
                   help="MB maximos por archivo (default 4)")
    p.add_argument("--format", choices=["human", "json"], default="human")

    # status
    p = sub.add_parser("status", help="Show project status")
    p.add_argument("--root", default=".")

    # analyze
    p = sub.add_parser("analyze", help="Analyze repo architecture")
    p.add_argument("--root", default=".")

    # release
    p = sub.add_parser("release", help="Check release readiness")
    p.add_argument("--root", default=".")

    # report · agregador
    p = sub.add_parser("report", help="Aggregate release + arena + SARIF + engagements")
    p.add_argument("--root", default=".")

    # compliance-report · mapea findings a LFPDPPP/PCI/SOX/etc
    p = sub.add_parser("compliance-report",
                       help="Map findings to LFPDPPP/PCI-DSS/SOX/CFF/OWASP")
    p.add_argument("--output", "-o",
                   help="Archivo destino (default stdout · requerido para pdf)")
    p.add_argument("--format", "-f",
                   choices=["md", "html", "pdf"], default="md",
                   help="Formato de salida (default md · pdf requiere weasyprint)")
    p.add_argument("--root", default=".")

    # security-scan-staged · para pre-commit hook
    p = sub.add_parser("security-scan-staged",
                       help="Scan archivos especificos (staged) · exit 1 si CRITICAL")
    p.add_argument("--stdin", action="store_true", help="Lee lista de archivos de stdin")
    p.add_argument("--files", nargs="+", help="Lista de archivos relativos al root")
    p.add_argument("--root", default=".")

    # trending · historical findings chart
    p = sub.add_parser("trending", help="ASCII chart de findings historicos (arena runs)")
    p.add_argument("--output", "-o", help="Archivo markdown destino")
    p.add_argument("--json", action="store_true", help="Output raw JSON en vez de markdown")
    p.add_argument("--root", default=".")

    # suppress · waivers file-based
    p = sub.add_parser("suppress", help="Manage findings suppressions/waivers")
    p.add_argument("action", choices=["list", "add", "check-expired"])
    p.add_argument("--rule-id", dest="rule_id", help="ej. STATIC-SQL-FSTRING")
    p.add_argument("--file", help="Path relativo al root del proyecto")
    p.add_argument("--line", type=int, default=0,
                   help="0 = wildcard toda la file")
    p.add_argument("--cwe", help="CWE-XX (informativo)")
    p.add_argument("--reason", help="Justificacion obligatoria")
    p.add_argument("--approver", help="Nombre del aprobador")
    p.add_argument("--approved-at", dest="approved_at",
                   help="ISO date (default: today)")
    p.add_argument("--expires-at", dest="expires_at",
                   help="ISO date · vacio = no expira")
    p.add_argument("--root", default=".")

    # engagement · invoca Nemesis scaffold
    p = sub.add_parser("engagement", help="Scaffold Nemesis engagement (AMX scope)")
    p.add_argument("--list", action="store_true", help="lista apps del catalogo")
    p.add_argument("--app", help="app_id del catalogo (ej. 02-arc)")
    p.add_argument("--all", action="store_true", help="genera todos los pending")
    p.add_argument("--quarter", help="quarter prefix (ej. 2026-Q2)")
    p.add_argument("--force", action="store_true", help="sobrescribe")
    p.add_argument("--dry-run", dest="dry_run", action="store_true")
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--root", default=".")

    # arena · adversarial self-play on-demand
    p = sub.add_parser("arena", help="Run Mythos vs Nemesis self-play (slow · manual)")
    p.add_argument("--target", help="TUT id (ej. amx-mini-refund)")
    p.add_argument("--target-url", dest="target_url",
                   help="URL HTTP del TUT live (activa nuclei)")
    p.add_argument("--max-rounds", dest="max_rounds", type=int, default=10)
    p.add_argument("--timeout", type=int, default=1200,
                   help="segundos antes de matar arena")
    p.add_argument("--list", action="store_true", help="lista TUTs disponibles")
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
    p.add_argument("action", nargs="?", choices=["init", "show", "set"], default="show", help="init, show, or set (default: show)")
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

    # refine
    p = sub.add_parser("refine", help="Analyze spec completeness")
    p.add_argument("--spec", help="Specific spec to refine")
    p.add_argument("--root", default=".")

    # sync
    p = sub.add_parser("sync", help="Sync AIOS to Kiro IDE format")
    p.add_argument("--root", default=".")

    # search
    p = sub.add_parser("search", help="Search codebase")
    p.add_argument("query", help="Search query")
    p.add_argument("--root", default=".")

    # changelog
    p = sub.add_parser("changelog", help="Generate/view changelog")
    p.add_argument("action", nargs="?", choices=["show", "generate"], default="show", help="show or generate (default: show)")
    p.add_argument("--commits", default="3", help="Number of commits")
    p.add_argument("--root", default=".")

    # clean
    p = sub.add_parser("clean", help="Clean AIOS artifacts")
    p.add_argument("--target", choices=["all", "changelog", "cache", "specs", "memory"], default="cache", help="What to clean")
    p.add_argument("--root", default=".")

    # scaffold-deploy-ready
    p = sub.add_parser(
        "scaffold-deploy-ready",
        help="Auto-detect app + scaffold deploy-ready package (docs · IaC · CI/CD · tests · runbook)",
    )
    p.add_argument("app_path", help="Path to app directory (e.g. apps/02-arc)")
    p.add_argument("--overwrite", action="store_true", help="Overwrite existing deploy-ready files")
    p.add_argument("--no-mythos", action="store_true", help="Skip Mythos TUT auto-registration")
    p.add_argument("--root", default=".", help="Repo root (for Mythos TUT lookup)")
    p.add_argument("--primary-stack", choices=["dotnet", "python", "java", "cobol", "php", "node"],
                   help="Force primary stack (override auto-detection) · use when target stack differs from current code")
    p.add_argument("--output-dir", help="Output dir (default: <app_path>/deploy-ready)")

    # version
    p = sub.add_parser("version", help="Show AIOS version")

    args = parser.parse_args()

    commands = {
        "init": cmd_init, "task": cmd_task, "boot": cmd_boot,
        "refresh": cmd_refresh, "status": cmd_status, "analyze": cmd_analyze,
        "release": cmd_release, "arena": cmd_arena, "engagement": cmd_engagement,
        "report": cmd_report, "compliance-report": cmd_compliance_report,
        "suppress": cmd_suppress, "trending": cmd_trending,
        "security-scan-staged": cmd_security_scan_staged,
        "doctor": cmd_doctor, "handoff": cmd_handoff,
        "module": cmd_module, "config": cmd_config, "version": cmd_version,
        "diff": cmd_diff, "impact": cmd_impact,
        "onboard": cmd_onboard, "guide": cmd_guide, "hook": cmd_hook, "mcp": cmd_mcp,
        "test": cmd_test, "progress": cmd_progress, "watch": cmd_watch, "cache": cmd_cache,
        "refine": cmd_refine, "sync": cmd_sync, "search": cmd_search,
        "changelog": cmd_changelog, "clean": cmd_clean,
        "scaffold-deploy-ready": cmd_scaffold_deploy_ready,
        # v1.7.3 · BUG-003 · resume + checkpoint
        "resume": cmd_resume, "checkpoint": cmd_checkpoint,
        # v1.9.0 · RFC-003 Nivel 2 · LLM classifier
        "classify": cmd_classify,
        # v2.0.0 · RFC-003 Nivel 3 · Characterization tests
        "characterize": cmd_characterize,
        # v2.1.0 · RFC-003 Nivel 4 · Stakeholder-in-the-Loop
        "review": cmd_review,
        # v2.2.0 · RFC-004a + 004b · Cross-Copy Drift Detector
        "drift": cmd_drift,
        # v2.3.0 · RFC-004c · Third-Party Exfil Heuristic
        "exfil": cmd_exfil,
        # v2.4.0 · RFC-004d · Runtime Data File Scanner
        "runtime-data": cmd_runtime_data,
        # v2.6.0 · Ensemble OSS scanner
        "ensemble": cmd_ensemble,
        # v2.8.0 · Dynamic analysis hooks
        "dynamic-hooks": cmd_dynamic_hooks,
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


def cmd_resume(args):
    """v1.7.3 · retoma sesion desde checkpoint guardado · BUG-003."""
    import json
    from aios.core.memory_engine import get_checkpoint, resume_instruction
    root = get_root(args)
    cp = get_checkpoint(root)
    if args.format == "json":
        print(json.dumps(cp, indent=2, ensure_ascii=False))
        return
    print()
    print("  AIOS Resume · checkpoint del workstream")
    print("  " + "─" * 60)
    if not any(cp.values()):
        print("  (sin checkpoint · workstream nuevo · empieza FASE 0)")
    else:
        if cp.get("phase_completed"):
            print(f"  Ultima fase completada: {cp['phase_completed']}")
        if cp.get("phase_in_progress"):
            print(f"  En progreso:            {cp['phase_in_progress']}")
        if cp.get("next_action"):
            print(f"  Proxima accion:         {cp['next_action']}")
        if cp.get("last_commit"):
            print(f"  Ultimo commit:          {cp['last_commit']}")
        if cp.get("updated"):
            print(f"  Updated:                {cp['updated']}")
    print()


def cmd_drift(args):
    """v2.2.0 · cross-copy drift detector · RFC-004a + RFC-004b."""
    import json
    from pathlib import Path as _Path
    from aios.core.drift_detector import detect_drift

    src = _Path(args.source)
    if not src.is_absolute():
        src = _Path.cwd() / src
    cmp = _Path(args.compare)
    if not cmp.is_absolute():
        cmp = _Path.cwd() / cmp
    if not src.exists():
        print(f"  ERROR · source no existe: {args.source}")
        return
    if not cmp.exists():
        print(f"  ERROR · compare no existe: {args.compare}")
        return

    severity_order = ["INFO", "MEDIUM", "HIGH", "CRITICAL"]
    min_idx = severity_order.index(args.severity_min)
    report = detect_drift(src, cmp)

    # Filter findings por severity-min
    filtered = [
        f for f in report.findings
        if severity_order.index(f.severity) >= min_idx
    ]

    if args.format == "json":
        out = report.to_dict()
        out["findings"] = [f.to_dict() for f in filtered]
        out["by_severity"] = {
            s: sum(1 for f in filtered if f.severity == s)
            for s in severity_order
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return

    print()
    print("  Cross-Copy Drift Analysis · RFC-004")
    print("  " + "─" * 68)
    print(f"  Source  : {report.root_a}")
    print(f"  Compare : {report.root_b}")
    print()
    print(f"  Config file pairs matched: {report.file_pairs_matched}")
    print(f"  Files only in source  : {len(report.files_only_in_a)}")
    print(f"  Files only in compare : {len(report.files_only_in_b)}")
    print()
    by_sev = {s: sum(1 for f in filtered if f.severity == s) for s in severity_order}
    print(f"  Findings by severity (min={args.severity_min}):")
    for s in reversed(severity_order):
        count = by_sev.get(s, 0)
        if count > 0:
            print(f"    {s:10s} : {count}")
    print()
    if filtered:
        # Critical + High primero · agrupados
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):
            sev_findings = [f for f in filtered if f.severity == sev]
            if not sev_findings:
                continue
            print(f"  ═══ {sev} ({len(sev_findings)}) ═══")
            for f in sev_findings[:20]:
                print(f"    · [{f.kind}] {f.key}")
                if f.file_a or f.file_b:
                    print(f"      A: {f.file_a or '(no presente)'}")
                    print(f"      B: {f.file_b or '(no presente)'}")
                if f.value_a or f.value_b:
                    v_a = f.value_a[:80] + "..." if len(f.value_a) > 80 else f.value_a
                    v_b = f.value_b[:80] + "..." if len(f.value_b) > 80 else f.value_b
                    print(f"      val A: {v_a}")
                    print(f"      val B: {v_b}")
                print(f"      → {f.message[:200]}")
                if f.extra_occurrences:
                    print(f"      Se repite en {len(f.extra_occurrences)} archivos:")
                    for occ in f.extra_occurrences[:5]:
                        print(f"        · {occ.get('file','')}:{occ.get('line',0)}")
                print()
    print()


def cmd_review(args):
    """v2.1.0 · stakeholder-in-the-loop · RFC-003 Nivel 4."""
    import json
    from datetime import datetime, timezone
    from aios.core import review as rv
    from aios.core.security_gate import run_security_gate
    root = get_root(args)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Determina usuario (git config si no --user)
    user = args.user
    if not user:
        try:
            import subprocess
            r = subprocess.run(["git", "config", "user.email"],
                               capture_output=True, text=True,
                               cwd=str(root), check=False, timeout=5)
            user = r.stdout.strip() or "anonymous"
        except Exception:  # noqa: BLE001
            user = "anonymous"

    if args.action == "list":
        # Corre scan + filtra por decisions
        sec = run_security_gate(root)
        pause = sec.get("requires_human_review", []) or []
        # v3.1 · auto-sync filesystem review docs con el scan actual.
        # Antes: list mostraba pending desde state en memoria · pero
        # .aios/reviews/*.md quedaba stale · clean-session validation lo
        # detecto. Ahora regenera .md files para toda finding pending que
        # no tenga doc persistido.
        reviews_dir = root / ".aios" / "reviews"
        reviews_dir.mkdir(parents=True, exist_ok=True)
        existing_md = {p.stem for p in reviews_dir.glob("*.md")}
        sync_count = 0
        for f in pause:
            fid = rv.make_finding_id(
                f.get("file", ""), int(f.get("line", 0) or 0),
                f.get("rule_id", ""),
            )
            if fid in existing_md:
                continue
            f_with_id = dict(f)
            f_with_id["finding_id"] = fid
            rv.generate_review_doc(f_with_id, root)
            sync_count += 1
        if sync_count and args.format != "json":
            print(f"  [sync] generados {sync_count} review docs "
                  f"nuevos en {reviews_dir}")
        buckets = rv.filter_findings_by_decisions(pause, root)
        if args.format == "json":
            print(json.dumps({
                "pending": buckets["pending"],
                "approved": len(buckets["approved"]),
                "rejected": len(buckets["rejected"]),
                "deferred": len(buckets["deferred"]),
            }, indent=2, ensure_ascii=False))
            return
        print()
        print(f"  Review queue")
        print(f"  ─────────────────────────────────────────────")
        print(f"  Pending  : {len(buckets['pending'])} findings")
        print(f"  Approved : {len(buckets['approved'])} (histórico)")
        print(f"  Rejected : {len(buckets['rejected'])} (bloquean release)")
        print(f"  Deferred : {len(buckets['deferred'])} (pospuestos)")
        print()
        if buckets["pending"]:
            print("  Pendientes:")
            for f in buckets["pending"][:20]:
                print(f"    · {f['finding_id']} · {f.get('rule_id','')} · "
                      f"{f.get('file','')}:{f.get('line','?')} · "
                      f"sev={f.get('severity','?')}")
        print()
        return

    if args.action == "generate":
        sec = run_security_gate(root)
        pause = sec.get("requires_human_review", []) or []
        count = 0
        for f in pause:
            fid = rv.make_finding_id(
                f.get("file", ""), int(f.get("line", 0) or 0),
                f.get("rule_id", ""),
            )
            f_with_id = dict(f)
            f_with_id["finding_id"] = fid
            rv.generate_review_doc(f_with_id, root)
            count += 1
        print()
        print(f"  {count} review docs generados en .aios/reviews/")
        print()
        return

    if args.action == "show":
        if not args.id:
            print("  ERROR · --id requerido")
            return
        doc = root / ".aios" / "reviews" / f"{args.id}.md"
        if not doc.exists():
            print(f"  ERROR · review doc no existe: {args.id}")
            print("  Corre 'aios review generate' primero")
            return
        print()
        print(doc.read_text(encoding="utf-8"))
        print()
        return

    if args.action in ("approve", "reject", "defer"):
        if not args.id:
            print(f"  ERROR · --id requerido para {args.action}")
            return
        # Find existing review doc para extraer metadata
        doc = root / ".aios" / "reviews" / f"{args.id}.md"
        file_path, line_no, rule_id = "", 0, ""
        if doc.exists():
            for line in doc.read_text(encoding="utf-8").splitlines():
                if line.startswith("**File:**"):
                    file_path = line.split("`", 2)[1] if "`" in line else ""
                elif line.startswith("**Line:**"):
                    import re as _re
                    m = _re.search(r"\d+", line)
                    if m:
                        line_no = int(m.group(0))
                elif line.startswith("**Rule:**"):
                    rule_id = line.split("`", 2)[1] if "`" in line else ""

        decision = rv.ReviewDecision(
            timestamp=now, finding_id=args.id,
            file=file_path, line=line_no, rule_id=rule_id,
            action=args.action, reason=args.reason, user=user,
            final_classification=args.classification,
            ontology_proposed=args.add_to_ontology and args.action == "approve",
        )
        rv.log_decision(root, decision)

        # Ontology proposal (optional)
        if args.add_to_ontology and args.action == "approve":
            snippet = ""
            if doc.exists():
                # Very heuristic · extract snippet line from markdown
                for line in doc.read_text(encoding="utf-8").splitlines():
                    if "snippet" in line.lower():
                        snippet = line
                        break
            proposal_path = rv.propose_ontology_entry(
                root, args.id, rule_id, snippet or "",
                args.classification or "unclear",
                args.reason or "Propuesto en review",
                pattern_override=args.pattern,
            )
            print(f"  ✓ Ontology proposal agregado a: {proposal_path}")
            print(f"    Merge manual al catálogo canónico tras aprobación AMX.")
        print()
        print(f"  ✓ Decision logged · {args.action.upper()} · {args.id}")
        if args.reason:
            print(f"    Reason: {args.reason}")
        print(f"    User  : {user}")
        print(f"    Time  : {now}")
        print()
        return


def cmd_characterize(args):
    """v2.0.0 · characterization tests · RFC-003 Nivel 3."""
    import json
    from aios.core import characterization as ch
    from pathlib import Path
    root = get_root(args)
    file_path = Path(args.file)
    if not file_path.is_absolute():
        file_path = root / file_path
    if not file_path.exists():
        print(f"  ERROR · archivo no existe: {args.file}")
        return

    if args.action == "capture":
        fp = ch.capture_file(file_path, root)
        out_path = ch.save_fingerprint(fp, root)
        if args.format == "json":
            print(json.dumps(fp.to_dict(), indent=2, ensure_ascii=False))
            return
        print()
        print(f"  Characterization captured · RFC-003 Nivel 3")
        print(f"  ─────────────────────────────────────────────")
        print(f"  File       : {fp.file}")
        print(f"  Language   : {fp.language}")
        print(f"  Captured   : {fp.captured_at}")
        print(f"  AST hash   : {fp.ast_hash}")
        print(f"  Line count : {fp.line_count}")
        print(f"  Classes    : {len(fp.classes)}")
        print(f"  Methods    : {len(fp.methods)}")
        print(f"  Fields     : {len(fp.fields)}")
        print(f"  Imports    : {len(fp.imports)}")
        print(f"  Saved to   : {out_path}")
        print()
        return

    if args.action == "show":
        rel = str(file_path.relative_to(root))
        fp = ch.load_fingerprint(rel, root)
        if fp is None:
            print(f"  (sin fingerprint previo para {rel})")
            return
        if args.format == "json":
            print(json.dumps(fp.to_dict(), indent=2, ensure_ascii=False))
            return
        print()
        print(f"  Fingerprint de {fp.file}")
        print(f"  ──────────────────────────────────")
        print(f"  Captured   : {fp.captured_at}")
        print(f"  AST hash   : {fp.ast_hash}")
        print(f"  Classes ({len(fp.classes)}):")
        for c in fp.classes[:10]:
            print(f"    · {c.kind} {c.name} : {','.join(c.bases) or '(no bases)'}")
        print(f"  Methods ({len(fp.methods)}):")
        for m in fp.methods[:15]:
            print(f"    · {m.canonical()[:100]}")
        if len(fp.methods) > 15:
            print(f"    · ... ({len(fp.methods) - 15} more)")
        print()
        return

    if args.action == "verify":
        result = ch.verify(file_path, root)
        if result is None:
            print(f"  ERROR · sin baseline · corre 'aios characterize capture' primero")
            return
        if args.format == "json":
            print(json.dumps({
                "file": result.file, "passed": result.passed,
                "deltas": [{"kind": d.kind, "severity": d.severity,
                            "element": d.element, "pre": d.pre,
                            "post": d.post, "message": d.message}
                           for d in result.deltas],
                "summary": result.summary,
                "by_severity": result.by_severity(),
            }, indent=2, ensure_ascii=False))
            return
        print()
        verdict = "PASS" if result.passed else "FAIL"
        print(f"  Characterization verify · {verdict}")
        print(f"  ─────────────────────────────────────────────")
        print(f"  File        : {result.file}")
        print(f"  AST hash    : {result.summary.get('pre_fingerprint')} -> "
              f"{result.summary.get('post_fingerprint')}")
        print(f"  Line delta  : {result.summary.get('line_delta')}")
        print(f"  By severity : {result.by_severity()}")
        print()
        for d in result.deltas:
            icon = {"CRITICAL": "XX", "WARN": "!!", "INFO": "ii"}.get(d.severity, "--")
            print(f"  [{icon}] {d.kind:20s} {d.element[:40]}")
            if d.pre and d.post:
                print(f"        pre : {d.pre[:100]}")
                print(f"        post: {d.post[:100]}")
            if d.message:
                print(f"        → {d.message[:150]}")
        print()
        if not result.passed:
            print("  ROLLBACK RECOMMENDED · CRITICAL deltas detected")
        print()
        return

    if args.action == "diff":
        if not args.vs:
            print("  ERROR · --vs requerido para diff · segundo archivo")
            return
        other = Path(args.vs)
        if not other.is_absolute():
            other = root / other
        if not other.exists():
            print(f"  ERROR · archivo --vs no existe: {args.vs}")
            return
        fp_a = ch.capture_file(file_path, root)
        fp_b = ch.capture_file(other, root)
        result = ch.diff_fingerprints(fp_a, fp_b)
        print()
        print(f"  Diff · {fp_a.file} vs {fp_b.file}")
        print(f"  ─────────────────────────────────────────────")
        print(f"  Hashes      : {fp_a.ast_hash} vs {fp_b.ast_hash}")
        print(f"  By severity : {result.by_severity()}")
        for d in result.deltas[:20]:
            print(f"  [{d.severity[:4]}] {d.kind:20s} {d.element[:50]}")
        print()
        return


def cmd_classify(args):
    """v1.9.0 · clasifica un finding con ontology + LLM · RFC-003 Nivel 2."""
    import json
    from aios.core.security_gate import Finding, _load_config
    from aios.core.ontology import load_ontology as _load_ont, classify_finding as _classify_ont
    root = get_root(args)
    cfg = _load_config(root)
    # Build finding desde args
    snippet = args.snippet
    if not snippet:
        try:
            fp = root / args.file
            lines = fp.read_text(encoding="utf-8", errors="ignore").splitlines()
            if 0 < args.line <= len(lines):
                snippet = lines[args.line - 1].strip()[:160]
        except OSError:
            snippet = ""
    finding = Finding(
        cwe="", severity=args.severity, rule_id=args.rule_id,
        file=args.file, line=args.line, snippet=snippet,
    )
    # Nivel 1 · ontology
    from aios.core.security_gate import _load_ontology_for_scan
    ontology = _load_ontology_for_scan(root, cfg)
    ont_result = _classify_ont(finding, ontology)
    finding.ontology_action = ont_result.action
    finding.ontology_match = ont_result.ontology_match
    finding.ontology_classification = ont_result.classification
    finding.ontology_message = ont_result.message
    # Nivel 2 · LLM (opt-in · skip si --no-llm)
    llm_result = None
    if not args.no_llm:
        from aios.core.llm_classifier import LLMClassifier
        llm_cfg = (cfg.get("llm_classifier") or {}).copy()
        if args.provider:
            llm_cfg["provider"] = args.provider
            llm_cfg["enabled"] = True
        if llm_cfg.get("enabled", False) or args.provider:
            try:
                clf = LLMClassifier.from_config(llm_cfg)
                llm_result = clf.classify(finding, root)
                finding.llm_classification = llm_result.classification
                finding.llm_confidence = llm_result.confidence
                finding.llm_reasoning = llm_result.reasoning
                finding.llm_evidence = list(llm_result.evidence)
                finding.llm_provider = llm_result.provider
                finding.llm_cached = llm_result.cached
                if llm_result.confidence >= clf.confidence_threshold:
                    finding.ontology_action = llm_result.recommended_action
                    finding.ontology_classification = llm_result.classification
            except Exception as exc:  # noqa: BLE001
                llm_result = None
                print(f"  (LLM error: {exc})")
    # Output
    if args.format == "json":
        out = {
            "finding": {
                "rule_id": finding.rule_id, "file": finding.file,
                "line": finding.line, "severity": finding.severity,
                "snippet": finding.snippet,
            },
            "ontology": {
                "action": finding.ontology_action,
                "match": finding.ontology_match,
                "classification": finding.ontology_classification,
                "message": finding.ontology_message,
            },
            "llm": {
                "classification": finding.llm_classification,
                "confidence": finding.llm_confidence,
                "reasoning": finding.llm_reasoning,
                "evidence": finding.llm_evidence,
                "provider": finding.llm_provider,
                "cached": finding.llm_cached,
            } if finding.llm_classification else None,
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return
    # Human
    print()
    print("  Classify · Domain Ontology + LLM (v1.9.0)")
    print("  " + "─" * 60)
    print(f"  Finding:  {finding.rule_id} · {finding.file}:{finding.line}")
    print(f"  Snippet:  {finding.snippet[:100]}")
    print()
    print(f"  [Nivel 1] ontology:")
    print(f"    action         : {finding.ontology_action}")
    print(f"    match          : {finding.ontology_match or '(ninguno)'}")
    print(f"    classification : {finding.ontology_classification}")
    if finding.ontology_message:
        print(f"    message        : {finding.ontology_message[:100]}")
    if llm_result:
        print()
        print(f"  [Nivel 2] LLM ({finding.llm_provider}, cached={finding.llm_cached}):")
        print(f"    classification : {finding.llm_classification}")
        print(f"    confidence     : {finding.llm_confidence:.2f}")
        print(f"    reasoning      : {finding.llm_reasoning[:200]}")
        if finding.llm_evidence:
            print(f"    evidence       : {', '.join(finding.llm_evidence[:5])}")
    print()


def cmd_checkpoint(args):
    """v1.7.3 · muestra o actualiza checkpoint · BUG-003."""
    from aios.core.memory_engine import get_checkpoint, update_checkpoint
    root = get_root(args)
    if args.show:
        cp = get_checkpoint(root)
        print()
        print("  Checkpoint actual:")
        for k, v in cp.items():
            print(f"    {k}: {v or '(empty)'}")
        print()
        return
    update_checkpoint(
        root,
        phase_completed=args.phase_completed,
        phase_in_progress=args.phase_in_progress,
        next_action=args.next_action,
        last_commit=args.last_commit,
    )
    print()
    print("  ✓ Checkpoint escrito en ai-memory/active_workstream.md")
    if args.phase_completed:
        print(f"    phase_completed: {args.phase_completed}")
    if args.phase_in_progress:
        print(f"    phase_in_progress: {args.phase_in_progress}")
    if args.next_action:
        print(f"    next_action: {args.next_action}")
    if args.last_commit:
        print(f"    last_commit: {args.last_commit}")
    print()


def cmd_exfil(args):
    """v2.3.0 · RFC-004c · third-party exfil heuristic."""
    import json
    from pathlib import Path as _Path
    from aios.core.exfil_detector import ExfilDetector

    root = _Path(args.root)
    if not root.is_absolute():
        root = _Path.cwd() / root
    if not root.exists():
        print(f"  ERROR · root no existe: {args.root}")
        return

    corp = [d.strip() for d in (args.corporate or "").split(",") if d.strip()] or None
    report = ExfilDetector(root, corporate_domains=corp).detect()

    severity_order = ["INFO", "MEDIUM", "HIGH"]
    min_idx = severity_order.index(args.severity_min)
    filtered = [
        f for f in report.findings
        if severity_order.index(f.severity) >= min_idx
    ]

    if args.format == "json":
        out = report.to_dict()
        out["findings"] = [f.to_dict() for f in filtered]
        out["by_severity"] = {
            s: sum(1 for f in filtered if f.severity == s)
            for s in severity_order
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return

    print()
    print("  Third-Party Exfil Heuristic · RFC-004c")
    print("  " + "─" * 68)
    print(f"  Root                : {report.root}")
    print(f"  Corporate whitelist : {', '.join(report.corporate_domains)}")
    print(f"  Files scanned       : {report.files_scanned}")
    print()
    by_sev = {s: sum(1 for f in filtered if f.severity == s) for s in severity_order}
    print(f"  Findings by severity (min={args.severity_min}):")
    for s in reversed(severity_order):
        count = by_sev.get(s, 0)
        if count > 0:
            print(f"    {s:10s} : {count}")
    print()
    if filtered:
        for sev in ("HIGH", "MEDIUM", "INFO"):
            sev_findings = [f for f in filtered if f.severity == sev]
            if not sev_findings:
                continue
            print(f"  ═══ {sev} ({len(sev_findings)}) ═══")
            for f in sev_findings[:30]:
                print(f"    · [{f.kind}] {f.domain} (env_hint={f.env_hint})")
                print(f"      {f.file}:{f.line}")
                print(f"      → {f.recipient}")
                print(f"      ctx: {f.context[:120]}")
                print()
    print()


def cmd_runtime_data(args):
    """v2.4.0 · RFC-004d · runtime data file scanner."""
    import json
    from pathlib import Path as _Path
    from aios.core.runtime_data_scanner import RuntimeDataScanner

    root = _Path(args.root)
    if not root.is_absolute():
        root = _Path.cwd() / root
    if not root.exists():
        print(f"  ERROR · root no existe: {args.root}")
        return

    max_bytes = max(1, args.max_mb) * 1024 * 1024
    report = RuntimeDataScanner(root, max_file_bytes=max_bytes).scan()

    severity_order = ["INFO", "MEDIUM", "HIGH"]
    min_idx = severity_order.index(args.severity_min)
    filtered = [
        f for f in report.findings
        if severity_order.index(f.severity) >= min_idx
    ]

    if args.format == "json":
        out = report.to_dict()
        out["findings"] = [f.to_dict() for f in filtered]
        out["by_severity"] = {
            s: sum(1 for f in filtered if f.severity == s)
            for s in severity_order
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return

    print()
    print("  Runtime Data Scanner · RFC-004d")
    print("  " + "─" * 68)
    print(f"  Root          : {report.root}")
    print(f"  Files scanned : {report.files_scanned}")
    print()
    by_sev = {s: sum(1 for f in filtered if f.severity == s) for s in severity_order}
    print(f"  Findings by severity (min={args.severity_min}):")
    for s in reversed(severity_order):
        count = by_sev.get(s, 0)
        if count > 0:
            print(f"    {s:10s} : {count}")
    print()
    if filtered:
        for sev in ("HIGH", "MEDIUM", "INFO"):
            sev_findings = [f for f in filtered if f.severity == sev]
            if not sev_findings:
                continue
            # Group by kind dentro del severity
            by_kind: dict[str, list] = {}
            for f in sev_findings:
                by_kind.setdefault(f.kind, []).append(f)
            print(f"  ═══ {sev} ({len(sev_findings)}) ═══")
            for kind, fs in by_kind.items():
                print(f"    [{kind}] · {len(fs)} findings")
                for f in fs[:10]:
                    print(f"      · {f.file}:{f.line} · sample={f.sample}")
                if len(fs) > 10:
                    print(f"      ... +{len(fs) - 10} more")
            print()
    print()


def cmd_ensemble(args):
    """v2.6.0 · Ensemble OSS scanner wrapper."""
    import json as _json
    from pathlib import Path as _Path
    from aios.core.ensemble_scanner import EnsembleScanner

    root = _Path(args.root)
    if not root.is_absolute():
        root = _Path.cwd() / root
    if not root.exists():
        print(f"  ERROR · root no existe: {args.root}")
        return

    tools = [t.strip() for t in (args.tools or "").split(",") if t.strip()] or None
    scanner = EnsembleScanner(root, tools=tools, timeout_per_tool=args.timeout)
    print(f"  Tools a correr: {scanner.tools or '(ninguno disponible)'}")
    report = scanner.scan()

    severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_idx = severity_order.index(args.severity_min)
    filtered = [
        f for f in report.findings
        if severity_order.index(f.severity) >= min_idx
    ]

    if args.format == "json":
        out = report.to_dict()
        out["findings"] = [f.to_dict() for f in filtered]
        out["by_severity"] = {
            s: sum(1 for f in filtered if f.severity == s)
            for s in severity_order
        }
        print(_json.dumps(out, indent=2, ensure_ascii=False))
        return

    print()
    print("  Ensemble OSS Scan · v2.6.0")
    print("  " + "─" * 68)
    print(f"  Root          : {report.root}")
    print(f"  Tools run     : {', '.join(report.tools_run) or 'ninguno'}")
    if report.tools_skipped:
        print("  Tools skipped :")
        for t, reason in report.tools_skipped.items():
            print(f"    · {t:<12} {reason}")
    print()
    print("  Per-tool counts:")
    for t, c in report.per_tool_counts.items():
        print(f"    {t:<12} {c}")
    print()
    by_sev = {s: sum(1 for f in filtered if f.severity == s) for s in severity_order}
    print(f"  Findings filtered (min={args.severity_min}):")
    for s in reversed(severity_order):
        count = by_sev.get(s, 0)
        if count > 0:
            print(f"    {s:10s} : {count}")
    print()
    if filtered:
        # Top 15 por severity
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev_findings = [f for f in filtered if f.severity == sev]
            if not sev_findings:
                continue
            print(f"  ═══ {sev} ({len(sev_findings)}) ═══")
            for f in sev_findings[:15]:
                print(f"    · [{f.tool}] {f.rule_id} · {f.cwe}")
                print(f"      {f.file}:{f.line}")
                print(f"      → {f.message[:160]}")
            print()
    print()


def cmd_dynamic_hooks(args):
    """v2.8.0 · genera test stubs + reglas Falco + sugerencias OTel."""
    import json as _json
    from pathlib import Path as _Path
    from aios.core.dynamic_hooks import generate_dynamic_hooks

    root = _Path(args.root)
    if not root.is_absolute():
        root = _Path.cwd() / root
    char_dir = _Path(args.characterization_dir) if args.characterization_dir else None
    findings: list[dict] = []
    if args.findings_file:
        try:
            raw = _Path(args.findings_file).read_text(encoding="utf-8")
            parsed = _json.loads(raw)
            if isinstance(parsed, dict):
                findings = parsed.get("findings", []) or []
            elif isinstance(parsed, list):
                findings = parsed
        except (OSError, _json.JSONDecodeError) as e:
            print(f"  WARN · no pude leer findings-file: {e}")

    report = generate_dynamic_hooks(root, char_dir, findings)

    if args.format == "json":
        print(_json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        return

    print()
    print("  Dynamic Hooks · v2.8.0")
    print("  " + "─" * 68)
    print(f"  Root                     : {report.root}")
    print(f"  Test stubs generated     : {len(report.test_stubs)}")
    print(f"  Falco rules emitted      : {len(report.falco_rules)}")
    print(f"  Instrumentation hotspots : {len(report.instrumentation_points)}")
    print()
    if report.test_stubs:
        print("  ═══ Test stubs (primeros 5) ═══")
        for s in report.test_stubs[:5]:
            print(f"    · [{s.language}] {s.target_class}.{s.target_method}()")
        print()
    if report.falco_rules:
        print("  ═══ Falco rules ═══")
        for r in report.falco_rules:
            print(f"    · {r.priority} · {r.name}")
        print()
    if report.instrumentation_points:
        print("  ═══ OTel spans sugeridos ═══")
        for pt in report.instrumentation_points[:10]:
            print(f"    · {pt['target']} → {pt['otel_span']}")
        print()


if __name__ == "__main__":
    main()
