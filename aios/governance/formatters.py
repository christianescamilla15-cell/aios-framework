"""AIOS Governance · formatters · output del CheckReport en text/json."""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime

from .models import CheckReport, CheckSeverity


# ANSI colors · degraded gracefully en pipes/CI
_COLORS = {
    CheckSeverity.PASS: "\033[32m",      # green
    CheckSeverity.WARN: "\033[33m",      # yellow
    CheckSeverity.FAIL: "\033[31m",      # red
    CheckSeverity.CRITICAL: "\033[1;31m", # bold red
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def format_text(report: CheckReport, use_color: bool = True) -> str:
    """Output text legible con colores ANSI."""

    def c(severity: CheckSeverity, label: str) -> str:
        if not use_color:
            return label
        return f"{_COLORS.get(severity, '')}{label}{_RESET}"

    lines: list[str] = []
    lines.append("=" * 72)
    lines.append(f"  AIOS Governance Check · app={report.app}")
    lines.append(f"  Timestamp: {report.timestamp.isoformat(timespec='seconds')}")
    lines.append("=" * 72)
    lines.append("")

    # Summary
    summary_parts = [
        f"  Total: {report.total}",
        c(CheckSeverity.CRITICAL, f"CRITICAL: {report.critical_count}"),
        c(CheckSeverity.FAIL, f"FAIL: {report.fail_count}"),
        c(CheckSeverity.WARN, f"WARN: {report.warn_count}"),
        c(CheckSeverity.PASS, f"PASS: {report.pass_count}"),
    ]
    lines.append(" · ".join(summary_parts))
    lines.append("")

    if report.is_passing:
        lines.append(c(CheckSeverity.PASS, f"  ✓ Estado general: PASSING"))
    else:
        lines.append(c(CheckSeverity.FAIL, f"  ✗ Estado general: FAILING"))
    lines.append("")

    # Findings agrupados por categoría
    cats = report.by_category()
    for cat in sorted(cats.keys()):
        lines.append(f"--- {cat.upper()} ({len(cats[cat])} findings) ---")
        for f in cats[cat]:
            sev_label = c(f.severity, f.severity.value)
            lines.append(f"  [{sev_label}] {f.rule_id}")
            lines.append(f"    {f.message}")
            if f.location:
                lines.append(f"    location: {f.location}")
            if f.suggestion:
                lines.append(f"    suggestion: {f.suggestion}")
            lines.append("")
        lines.append("")

    # Footer
    lines.append("=" * 72)
    if report.is_passing:
        lines.append(c(CheckSeverity.PASS, "  Result: PASS · ready to proceed"))
    else:
        lines.append(c(CheckSeverity.FAIL, "  Result: FAIL · resolver findings antes de continuar"))
    lines.append("=" * 72)

    return "\n".join(lines)


def format_json(report: CheckReport) -> str:
    """Output JSON estructurado · útil para CI/CD parsing."""
    payload = {
        "app": report.app,
        "timestamp": report.timestamp.isoformat(),
        "summary": {
            "total": report.total,
            "critical": report.critical_count,
            "fail": report.fail_count,
            "warn": report.warn_count,
            "pass": report.pass_count,
            "is_passing": report.is_passing,
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "category": f.category,
                "message": f.message,
                "location": f.location,
                "suggestion": f.suggestion,
            }
            for f in report.findings
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
