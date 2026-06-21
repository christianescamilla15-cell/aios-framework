"""v3.5.0 · ACME Compliance Checker (F01 + F07).

Verifica el cumplimiento de badges de gobernanza ACME al estilo de
`BO-ACME/CS_Scripts/check-compliance.sh` · sin dependencia externa.

Si el script shell oficial (`check-compliance.sh`) está en PATH (instalado
desde CS_Scripts vía `install-global-scripts.sh`), se delega · de lo
contrario corre la implementación nativa en Python.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List


JIRA_PATTERN = re.compile(r"\b[A-Z]{2,}-\d+\b")


def check_compliance(root: Path) -> Dict:
    """Retorna dict con resultados F01 + F07."""
    native_shell = shutil.which("check-compliance.sh")
    if native_shell:
        try:
            proc = subprocess.run(
                [native_shell], cwd=str(root),
                capture_output=True, text=True, timeout=30,
            )
            return {
                "mode": "delegated",
                "script": native_shell,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "returncode": proc.returncode,
            }
        except (subprocess.TimeoutExpired, OSError) as exc:
            return {"mode": "delegated", "error": str(exc)}

    results: Dict = {"mode": "native", "checks": {}}

    readme = root / "README.md"
    if readme.exists():
        txt = readme.read_text(encoding="utf-8", errors="ignore")
        f01 = ("F01_BADGE_START" in txt or "F01%20Compliance" in txt
               or "F01 Compliance" in txt)
        f01_pct = _extract_badge_pct(txt, "F01")
        results["checks"]["F01"] = {
            "present": f01,
            "percentage": f01_pct,
            "status": "pass" if f01 else "info",
            "detail": (
                f"Badge F01 presente ({f01_pct}%)" if f01 and f01_pct else
                "Badge F01 presente (sin % extraído)" if f01 else
                "Sin badge F01 · opcional en apps ACME bajo gobernanza"
            ),
        }
        f07 = ("F07_BADGE_START" in txt or "F07%20JIRA" in txt
               or "F07 JIRA" in txt)
        f07_pct = _extract_badge_pct(txt, "F07")
        results["checks"]["F07"] = {
            "present": f07,
            "percentage": f07_pct,
            "status": "pass" if f07 else "info",
            "detail": (
                f"Badge F07 JIRA Traceability ({f07_pct}%)"
                if f07 and f07_pct else
                "Badge F07 JIRA Traceability presente"
                if f07 else
                "Sin badge F07 · considera medir trazabilidad JIRA"
            ),
        }
    else:
        results["checks"]["F01"] = {"present": False, "status": "warn",
                                     "detail": "README.md no existe"}
        results["checks"]["F07"] = {"present": False, "status": "warn",
                                     "detail": "README.md no existe"}

    jira_stats = _jira_traceability(root)
    if jira_stats is not None:
        ratio = jira_stats["ratio"]
        status = "pass" if ratio >= 0.8 else "warn" if ratio >= 0.5 else "fail"
        results["checks"]["F07_commits"] = {
            "status": status,
            "detail": (
                f"{jira_stats['with_jira']}/{jira_stats['total']} commits "
                f"recientes con referencia JIRA "
                f"({int(ratio * 100)}%)"
            ),
            **jira_stats,
        }

    return results


def _extract_badge_pct(txt: str, key: str) -> int | None:
    m = re.search(
        rf"{key}[%\s]*(?:20)?(?:Compliance|JIRA[%\s]+(?:20)?Traceability)"
        rf"[%\s]*-(\d+)(?:%25|%)",
        txt,
    )
    return int(m.group(1)) if m else None


def _jira_traceability(root: Path, limit: int = 20) -> Dict | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "log",
             f"-n{limit}", "--pretty=%s"],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            return None
        subjects = [s for s in proc.stdout.splitlines() if s.strip()]
        if not subjects:
            return None
        with_jira = sum(1 for s in subjects if JIRA_PATTERN.search(s))
        return {
            "total": len(subjects),
            "with_jira": with_jira,
            "ratio": with_jira / len(subjects),
        }
    except (subprocess.TimeoutExpired, OSError):
        return None


def format_report(results: Dict) -> List[str]:
    lines: List[str] = []
    lines.append("")
    lines.append("=" * 60)
    lines.append("  ACME COMPLIANCE CHECK (F01 + F07)")
    lines.append("=" * 60)
    mode = results.get("mode")
    if mode == "delegated":
        lines.append("  Mode · delegated to check-compliance.sh (CS_Scripts)")
        lines.append(f"  Script · {results.get('script')}")
        lines.append(f"  Exit code · {results.get('returncode')}")
        stdout = results.get("stdout", "")
        if stdout:
            lines.append("  Output:")
            for ln in stdout.splitlines():
                lines.append(f"    {ln}")
        return lines
    lines.append("  Mode · native · CS_Scripts/check-compliance.sh no en PATH")
    for key, info in results.get("checks", {}).items():
        status = info.get("status", "?").upper()
        marker = ("[OK]" if status == "PASS" else "[XX]" if status == "FAIL"
                  else "[!!]" if status == "WARN" else "[..]")
        lines.append(f"  {marker} {key:<15} · {info.get('detail', '-')}")
    lines.append("=" * 60)
    return lines
