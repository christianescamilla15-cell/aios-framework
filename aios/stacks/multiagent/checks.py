"""Multiagent stack checks — validates agent architecture patterns."""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List
from aios.core.file_scanner import scan_tracked_files, scan_source_files


def run_checks(root: Path) -> List[Dict]:
    results = []
    src_files = scan_source_files(root, [".py", ".js", ".ts"])
    all_files = scan_tracked_files(root)

    # Check 1: Orchestrator
    found_orch = any("orchestrat" in str(f).lower() for f in src_files)
    results.append({"check": "Orchestrator pattern", "status": "pass" if found_orch else "warn"})

    # Check 2: Agent files
    agent_files = [f for f in src_files if "agent" in str(f).lower()]
    results.append({"check": f"Agent files ({len(agent_files)})", "status": "pass" if len(agent_files) >= 2 else "warn"})

    # Check 3: No hardcoded API keys
    suspicious = []
    for f in src_files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            if any(k in content for k in ["sk-ant-", "gsk_", "AKIA"]):
                if ".env" not in str(f):
                    suspicious.append(str(f.relative_to(root)))
        except Exception:
            pass
    results.append({"check": "No hardcoded API keys", "status": "fail" if suspicious else "pass",
                     "detail": f"Found in: {suspicious[:3]}" if suspicious else "Clean"})

    # Check 4: Rate limit handling
    has_rl = any("rate_limit" in f.read_text(encoding="utf-8", errors="ignore").lower() or "429" in f.read_text(encoding="utf-8", errors="ignore") for f in src_files if f.suffix == ".py")
    results.append({"check": "Rate limit handling", "status": "pass" if has_rl else "warn"})

    # Check 5: Audit logging
    has_audit = any("audit" in str(f).lower() or "change_log" in str(f).lower() for f in all_files)
    results.append({"check": "Audit logging", "status": "pass" if has_audit else "warn"})

    # Check 6: Env config
    has_env = any(".env.example" in f or ".env.sample" in f for f in all_files)
    results.append({"check": ".env.example exists", "status": "pass" if has_env else "warn"})

    return results
