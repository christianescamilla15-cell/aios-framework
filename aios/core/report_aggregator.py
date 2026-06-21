"""Report aggregator · consolida outputs de aios en un solo markdown.

Integra:
- release gate result (embedded security scan + checks AIOS)
- ultimo run Arena (de ai-memory/security_findings.md)
- engagements scaffolded (nemesis-engagements/_catalog + dirs con roe.yaml)
- Arena SARIF findings si existen (arena-memory/runs/<id>/findings.sarif)

Output: `reports/aios_report_<timestamp>.md`
"""

from __future__ import annotations

import glob
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .arena_runner import read_last_arena_run
from .release_gate import check_release_readiness


@dataclass
class ReportSection:
    title: str
    body: str = ""
    status: str = "info"  # info · pass · warn · fail


@dataclass
class AggregateReport:
    generated_at: str
    root: str
    sections: list[ReportSection] = field(default_factory=list)

    def to_markdown(self) -> str:
        out = [
            f"# AIOS Aggregate Report · {self.generated_at}",
            "",
            f"**Root:** `{self.root}`",
            "",
        ]
        for s in self.sections:
            out.append(f"## {s.title}")
            out.append("")
            if s.body:
                out.append(s.body)
            out.append("")
        return "\n".join(out)


def _section_release(root: Path) -> ReportSection:
    try:
        result = check_release_readiness(root)
    except Exception as exc:  # noqa: BLE001
        return ReportSection(
            title="Release Gate", status="warn",
            body=f"_No se pudo evaluar_: {exc}",
        )

    lines = [
        f"**Ready for release:** {'YES' if result['ready'] else 'NO'}",
        "",
        f"- Passed: {result['passed']}",
        f"- Warned: {result['warned']}",
        f"- Failed: {result['failed']}",
        "",
        "### Checks",
        "",
        "| Check | Status | Detail |",
        "|---|---|---|",
    ]
    for c in result["checks"]:
        d = (c.get("detail") or "").replace("|", "\\|")
        lines.append(f"| {c['check']} | {c['status']} | {d} |")

    sec = result.get("security", {})
    top = sec.get("top_findings", [])
    if top:
        lines.extend(["", "### Top security findings", "",
                      "| Severity | CWE | Rule | Location |",
                      "|---|---|---|---|"])
        for f in top:
            lines.append(
                f"| {f['severity']} | {f['cwe']} | {f['rule_id']} | "
                f"{f['file']}:{f['line']} |"
            )

    status = "pass" if result["ready"] else (
        "fail" if result["failed"] else "warn"
    )
    return ReportSection(title="Release Gate", body="\n".join(lines), status=status)


def _section_last_arena(root: Path) -> ReportSection:
    last = read_last_arena_run(root)
    if not last:
        return ReportSection(
            title="Last Arena self-play run", status="info",
            body="_No hay runs registrados en `ai-memory/security_findings.md`._",
        )
    verdict_status = {
        "MYTHOS_WINS": "pass", "NEMESIS_WINS": "fail",
        "STALEMATE": "warn", "DRAW": "info", "USER_STOPPED": "info",
    }.get(last.get("verdict") or "", "info")
    body = (
        f"- **Target:** `{last['target']}`\n"
        f"- **Verdict:** `{last.get('verdict') or 'N/A'}`\n"
        f"- **Timestamp:** {last['timestamp']}\n"
    )
    return ReportSection(title="Last Arena self-play run",
                         body=body, status=verdict_status)


def _find_arena_sarifs(root: Path, limit: int = 5) -> list[Path]:
    """Busca findings.sarif recientes en arena-memory/runs/."""
    candidates: list[Path] = []
    # Ubicaciones comunes
    for rel in ["arena/arena-memory/runs", "arena-memory/runs",
                "../acme-hallazgos-audit/arena/arena-memory/runs"]:
        p = (root / rel).resolve() if not rel.startswith("/") else Path(rel)
        if p.exists():
            candidates.extend(sorted(p.glob("*/findings.sarif"),
                                     key=lambda x: x.stat().st_mtime, reverse=True))
    return candidates[:limit]


def _section_sarif_summary(root: Path) -> ReportSection:
    sarifs = _find_arena_sarifs(root)
    if not sarifs:
        return ReportSection(
            title="Arena SARIF findings (recent runs)",
            body="_No hay findings.sarif encontrados._", status="info",
        )
    lines = ["| Run | Verdict | Rules | Findings | Nemesis confirmed |",
             "|---|---|---|---|---|"]
    total_findings = 0
    for sarif_path in sarifs:
        try:
            data = json.loads(sarif_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        run = (data.get("runs") or [{}])[0]
        props = run.get("properties") or {}
        rules = len(run.get("tool", {}).get("driver", {}).get("rules", []))
        results = len(run.get("results") or [])
        total_findings += results
        run_id = props.get("arena_run_id", sarif_path.parent.name)
        lines.append(
            f"| `{run_id}` | {props.get('verdict', 'N/A')} | "
            f"{rules} | {results} | "
            f"{props.get('nemesis_confirmed_exploits', 0)} |"
        )
    lines.append("")
    lines.append(f"**Total findings (recent {len(sarifs)} runs):** {total_findings}")
    status = "warn" if total_findings else "pass"
    return ReportSection(title="Arena SARIF findings (recent runs)",
                         body="\n".join(lines), status=status)


def _section_engagements(root: Path) -> ReportSection:
    """Lista engagements existentes en nemesis-engagements/ si hay."""
    candidates = [
        root / "nemesis" / "nemesis-engagements",
        root / "../acme-hallazgos-audit/nemesis/nemesis-engagements",
        Path("/mnt/c/Users/eTriber/Desktop/acme-hallazgos-audit/nemesis/nemesis-engagements"),
    ]
    base = next((p for p in candidates if p.exists()), None)
    if base is None:
        return ReportSection(
            title="Nemesis engagements", status="info",
            body="_No se localizo el directorio nemesis-engagements._",
        )
    engagements = [d for d in base.iterdir()
                   if d.is_dir() and not d.name.startswith("_")]
    if not engagements:
        return ReportSection(title="Nemesis engagements", status="info",
                             body="_Sin engagements scaffolded._")
    lines = ["| Engagement | RoE firmadas | Status |", "|---|---|---|"]
    for eng in sorted(engagements, key=lambda d: d.name):
        roe = eng / "roe.yaml"
        signed = "-"
        status = "frozen"
        if roe.exists():
            text = roe.read_text(encoding="utf-8")
            signed = "YES" if "approver_signatures_verified: true" in text else "NO"
            if "2099-01-01" in text:
                status = "frozen (2099 placeholder)"
            else:
                status = "active window configured"
        lines.append(f"| `{eng.name}` | {signed} | {status} |")
    return ReportSection(title="Nemesis engagements",
                         body="\n".join(lines), status="info")


def build_report(root: Path) -> AggregateReport:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report = AggregateReport(
        generated_at=now,
        root=str(root),
        sections=[
            _section_release(root),
            _section_last_arena(root),
            _section_sarif_summary(root),
            _section_engagements(root),
        ],
    )
    return report


def write_report(root: Path, report: AggregateReport) -> Path:
    """Escribe el reporte bajo reports/aios_report_<ts>.md."""
    reports_dir = root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = report.generated_at.replace(":", "-").replace("+00-00", "Z")
    dest = reports_dir / f"aios_report_{ts}.md"
    dest.write_text(report.to_markdown(), encoding="utf-8")
    return dest
