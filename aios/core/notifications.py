"""Webhook notifications · envia alertas a Slack/generic HTTPS cuando
el security gate bloquea en CI o local.

Config en aios-config.json:
{
  "notifications": {
    "slack_webhook": "https://hooks.slack.com/services/XXX/YYY/ZZZ",
    "on_block": true,
    "on_arena_verdict": ["NEMESIS_WINS"],
    "env_override": "AIOS_SLACK_WEBHOOK"
  }
}

Design:
- Zero dependencies · usa urllib de stdlib
- Config puede overridearse via env var (para CI sin commitear secrets)
- Silent graceful · si el webhook falla, no interrumpe el gate
- Timeout 5s · no bloquea CI si Slack esta caido
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class NotificationResult:
    sent: bool
    provider: str
    detail: str = ""


def _load_notif_config(root: Path) -> dict:
    cfg_file = root / "aios-config.json"
    if not cfg_file.exists():
        return {}
    try:
        data = json.loads(cfg_file.read_text(encoding="utf-8"))
        return data.get("notifications", {}) or {}
    except (json.JSONDecodeError, OSError):
        return {}


def _resolve_webhook(cfg: dict) -> Optional[str]:
    """Priority: env var override > config file."""
    env_key = cfg.get("env_override", "AIOS_SLACK_WEBHOOK")
    from_env = os.environ.get(env_key, "").strip()
    if from_env:
        return from_env
    from_cfg = (cfg.get("slack_webhook") or "").strip()
    return from_cfg or None


def send_slack(
    webhook_url: str,
    text: str,
    title: Optional[str] = None,
    severity_color: str = "warning",
    timeout_seconds: int = 5,
) -> NotificationResult:
    """POST al webhook Slack-compatible (Slack, Discord, Teams via bridge)."""
    # Slack incoming webhook format
    payload: dict = {"text": text}
    if title:
        color = {
            "good": "#10b981",
            "warning": "#f59e0b",
            "danger": "#ef4444",
        }.get(severity_color, severity_color)
        payload["attachments"] = [{
            "color": color,
            "title": title,
            "text": text,
            "mrkdwn_in": ["text", "pretext"],
        }]
        payload["text"] = title  # fallback para clients que no parsean attachments

    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            ok = resp.status < 400
            return NotificationResult(
                sent=ok, provider="slack",
                detail=f"status={resp.status}" + (f" · {body[:100]}" if body else ""),
            )
    except urllib.error.HTTPError as exc:
        return NotificationResult(
            sent=False, provider="slack",
            detail=f"HTTP {exc.code} · {exc.reason}",
        )
    except urllib.error.URLError as exc:
        return NotificationResult(
            sent=False, provider="slack",
            detail=f"URL error: {exc.reason}",
        )
    except Exception as exc:  # noqa: BLE001
        return NotificationResult(
            sent=False, provider="slack",
            detail=f"error: {exc}",
        )


def notify_release_blocked(
    root: Path,
    findings_summary: dict,
    top_findings: list[dict],
    project_name: Optional[str] = None,
) -> Optional[NotificationResult]:
    """Envia notificacion si config.notifications.on_block es true y
    hay webhook configurado. Retorna None si no hay webhook o
    on_block=false · NotificationResult si intento enviar."""
    cfg = _load_notif_config(root)
    if not cfg.get("on_block", True):
        return None
    webhook = _resolve_webhook(cfg)
    if not webhook:
        return None

    project = project_name or root.name
    crit = findings_summary.get("CRITICAL", 0)
    high = findings_summary.get("HIGH", 0)
    lines = [
        f":no_entry: *AIOS release gate BLOCKED* · `{project}`",
        f"*{crit}* CRITICAL · *{high}* HIGH findings",
        "",
        "*Top findings:*",
    ]
    for f in top_findings[:5]:
        lines.append(
            f"• `{f.get('cwe', '?')}` · `{f.get('rule_id', '?')}` · "
            f"`{f.get('file', '?')}:{f.get('line', 0)}`"
        )
    return send_slack(
        webhook, "\n".join(lines),
        title=f"AIOS · release blocked · {project}",
        severity_color="danger",
    )


def notify_arena_verdict(
    root: Path,
    verdict: str,
    target: str,
    rounds: int,
) -> Optional[NotificationResult]:
    """Notifica verdict de Arena run si config.on_arena_verdict
    incluye el verdict."""
    cfg = _load_notif_config(root)
    verdicts = cfg.get("on_arena_verdict", [])
    if not verdicts or verdict not in verdicts:
        return None
    webhook = _resolve_webhook(cfg)
    if not webhook:
        return None

    icon = {
        "MYTHOS_WINS": ":shield:",
        "NEMESIS_WINS": ":crossed_swords:",
        "STALEMATE": ":hourglass:",
        "DRAW": ":handshake:",
        "USER_STOPPED": ":stop_button:",
    }.get(verdict, ":warning:")
    color = {
        "MYTHOS_WINS": "good",
        "NEMESIS_WINS": "danger",
        "STALEMATE": "warning",
    }.get(verdict, "warning")

    project = root.name
    text = (
        f"{icon} *Arena verdict · {verdict}*\n"
        f"project: `{project}` · target: `{target}` · rounds: {rounds}"
    )
    return send_slack(
        webhook, text,
        title=f"Arena · {verdict} · {target}",
        severity_color=color,
    )
