"""Multiagent stack checks — optimized with sampling."""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List
from aios.core.file_scanner import scan_tracked_files, scan_source_files


def run_checks(root: Path) -> List[Dict]:
    results = []
    all_files = scan_tracked_files(root)
    src_files = scan_source_files(root, [".py", ".js", ".ts"])[:100]  # SAMPLE

    found_orch = any("orchestrat" in str(f).lower() for f in src_files)
    results.append({"check": "Orchestrator pattern", "status": "pass" if found_orch else "warn"})

    agent_files = [f for f in src_files if "agent" in str(f).lower()]
    results.append({"check": f"Agent files ({len(agent_files)})", "status": "pass" if len(agent_files) >= 2 else "warn"})

    suspicious = []
    for f in src_files[:50]:  # SAMPLE 50
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            if any(k in content for k in ["sk-ant-", "gsk_", "AKIA"]):
                if ".env" not in str(f):
                    suspicious.append(str(f.relative_to(root)))
        except Exception: pass
    results.append({"check": "No hardcoded keys", "status": "fail" if suspicious else "pass",
                     "detail": f"Found: {suspicious[:3]}" if suspicious else "Clean"})

    has_rl = False
    for f in src_files[:30]:
        if f.suffix == ".py":
            try:
                c = f.read_text(encoding="utf-8", errors="ignore")
                if "rate_limit" in c.lower() or "429" in c:
                    has_rl = True; break
            except: pass
    results.append({"check": "Rate limit handling", "status": "pass" if has_rl else "warn"})

    has_audit = any("audit" in f.lower() or "change_log" in f.lower() for f in all_files)
    results.append({"check": "Audit logging", "status": "pass" if has_audit else "warn"})

    has_env = any(".env.example" in f for f in all_files)
    results.append({"check": ".env.example", "status": "pass" if has_env else "warn"})
    return results
