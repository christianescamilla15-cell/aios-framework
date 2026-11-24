"""Findings trending · aggregacion historica de scans + runs.

Lee:
- `reports/aios_report_*.md` (snapshots del aggregator)
- `arena-memory/runs/*/metadata.json` (runs Arena)
- `ai-memory/security_findings.md` (runs Arena resumidos)

Genera series temporales · findings_count vs date · por marco
regulatorio o por severity. Output · ASCII chart para terminal +
HTML chart embebido para el WebView dashboard.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Iterable


@dataclass
class DataPoint:
    date_iso: str
    target: str
    verdict: str
    findings_count: int
    critical: int = 0
    high: int = 0


def _parse_iso_date(s: str) -> str | None:
    """Retorna YYYY-MM-DD si el str es parseable como ISO · None si no."""
    if not s:
        return None
    try:
        return s[:10]  # heuristica · agarra YYYY-MM-DD del inicio
    except Exception:  # noqa: BLE001
        return None


def _collect_arena_runs(root: Path) -> list[DataPoint]:
    """Lee metadata.json de cada run bajo arena-memory/runs/."""
    out: list[DataPoint] = []
    for runs_dir in (
        root / "arena" / "arena-memory" / "runs",
        root / "arena-memory" / "runs",
    ):
        if not runs_dir.exists():
            continue
        for run in sorted(runs_dir.iterdir()):
            if not run.is_dir():
                continue
            meta_file = run / "metadata.json"
            if not meta_file.exists():
                continue
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            findings = 0
            critical = 0
            high = 0
            sarif = run / "findings.sarif"
            if sarif.exists():
                try:
                    sdoc = json.loads(sarif.read_text(encoding="utf-8"))
                    results = sdoc.get("runs", [{}])[0].get("results", [])
                    findings = len(results)
                    for r in results:
                        lvl = r.get("level", "").lower()
                        sev = r.get("properties", {}).get("severity", "").upper()
                        if sev == "CRITICAL" or lvl == "error":
                            critical += 1
                        elif sev == "HIGH":
                            high += 1
                except (json.JSONDecodeError, OSError):
                    pass

            d = _parse_iso_date(meta.get("started_at", ""))
            if not d:
                continue
            out.append(DataPoint(
                date_iso=d,
                target=meta.get("target_id", "?"),
                verdict=meta.get("verdict", "?"),
                findings_count=findings,
                critical=critical,
                high=high,
            ))
    return out


def _group_by_date(points: Iterable[DataPoint]) -> dict[str, dict]:
    """Aggregate findings totales por fecha · sum across targets."""
    daily: dict[str, dict] = {}
    for p in points:
        bucket = daily.setdefault(p.date_iso, {
            "findings": 0, "critical": 0, "high": 0, "runs": 0, "targets": set(),
        })
        bucket["findings"] += p.findings_count
        bucket["critical"] += p.critical
        bucket["high"] += p.high
        bucket["runs"] += 1
        bucket["targets"].add(p.target)
    # Normalize set → sorted list para JSON-safe
    for bucket in daily.values():
        bucket["targets"] = sorted(bucket["targets"])
    return daily


def render_ascii_chart(
    daily: dict[str, dict],
    width: int = 60,
    field: str = "findings",
) -> str:
    """Chart ASCII horizontal de barras por dia."""
    if not daily:
        return "(sin datos historicos)"
    dates = sorted(daily.keys())
    values = [daily[d][field] for d in dates]
    max_val = max(values) if values else 0
    if max_val == 0:
        return "\n".join(f"  {d}  · 0" for d in dates)

    lines = [f"  {'date':<12} {'count':>5}  {'bar':<{width}}"]
    lines.append(f"  {'-' * 12} {'-' * 5}  {'-' * width}")
    for d in dates:
        n = daily[d][field]
        bar_len = int(round(n / max_val * width))
        bar = "█" * bar_len
        lines.append(f"  {d:<12} {n:>5}  {bar}")
    return "\n".join(lines)


def build_trending(root: Path) -> dict:
    """Entry point · retorna dict con daily aggregation + totals."""
    points = _collect_arena_runs(root)
    daily = _group_by_date(points)
    total_runs = len(points)
    total_findings = sum(p.findings_count for p in points)
    return {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "root": str(root),
        "total_arena_runs": total_runs,
        "total_findings": total_findings,
        "daily": daily,
        "points": [p.__dict__ for p in points],
    }


def render_trending_markdown(data: dict) -> str:
    lines = [
        f"# Findings Trending",
        "",
        f"**Generated:** {data['generated_at']}",
        f"**Total Arena runs:** {data['total_arena_runs']}",
        f"**Total findings (SARIF):** {data['total_findings']}",
        "",
        "## Findings por dia",
        "",
        "```",
        render_ascii_chart(data["daily"], field="findings"),
        "```",
        "",
        "## CRITICAL por dia",
        "",
        "```",
        render_ascii_chart(data["daily"], field="critical"),
        "```",
        "",
    ]
    if data["points"]:
        lines.extend([
            "## Runs individuales",
            "",
            "| Date | Target | Verdict | Findings | CRITICAL | HIGH |",
            "|---|---|---|---|---|---|",
        ])
        for p in data["points"][-30:]:
            lines.append(
                f"| {p['date_iso']} | `{p['target']}` | {p['verdict']} | "
                f"{p['findings_count']} | {p['critical']} | {p['high']} |"
            )
    return "\n".join(lines)
