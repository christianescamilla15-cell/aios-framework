"""Tests · webhook notifications · Slack + config."""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from aios.core.notifications import (
    _load_notif_config,
    _resolve_webhook,
    notify_arena_verdict,
    notify_release_blocked,
    send_slack,
)


def test_config_empty_if_no_file(tmp_path):
    assert _load_notif_config(tmp_path) == {}


def test_config_loads_notifications_section(tmp_path):
    (tmp_path / "aios-config.json").write_text(json.dumps({
        "notifications": {
            "slack_webhook": "https://hooks.slack.com/x",
            "on_block": True,
        }
    }))
    cfg = _load_notif_config(tmp_path)
    assert cfg["slack_webhook"].startswith("https://hooks.slack.com")


def test_resolve_webhook_env_override(monkeypatch):
    monkeypatch.setenv("AIOS_SLACK_WEBHOOK", "https://env.example/x")
    url = _resolve_webhook({"slack_webhook": "https://cfg.example/x"})
    assert url == "https://env.example/x"


def test_resolve_webhook_falls_back_to_config(monkeypatch):
    monkeypatch.delenv("AIOS_SLACK_WEBHOOK", raising=False)
    url = _resolve_webhook({"slack_webhook": "https://cfg.example/x"})
    assert url == "https://cfg.example/x"


def test_resolve_webhook_none_when_unconfigured(monkeypatch):
    monkeypatch.delenv("AIOS_SLACK_WEBHOOK", raising=False)
    assert _resolve_webhook({}) is None


def test_send_slack_success():
    fake_resp = MagicMock()
    fake_resp.status = 200
    fake_resp.read.return_value = b"ok"
    fake_resp.__enter__ = lambda self: self
    fake_resp.__exit__ = lambda *a: None
    with patch("aios.core.notifications.urllib.request.urlopen", return_value=fake_resp):
        r = send_slack("https://hooks.slack.com/x", "test")
    assert r.sent is True
    assert "status=200" in r.detail


def test_send_slack_http_error():
    err = urllib.error.HTTPError("https://x", 503, "Service Unavailable", {}, None)
    with patch("aios.core.notifications.urllib.request.urlopen", side_effect=err):
        r = send_slack("https://hooks.slack.com/x", "test")
    assert r.sent is False
    assert "503" in r.detail


def test_send_slack_url_error():
    err = urllib.error.URLError("network down")
    with patch("aios.core.notifications.urllib.request.urlopen", side_effect=err):
        r = send_slack("https://hooks.slack.com/x", "test")
    assert r.sent is False
    assert "network down" in r.detail


def test_notify_blocked_skipped_when_no_config(tmp_path):
    # No aios-config.json · no webhook · retorna None
    result = notify_release_blocked(
        tmp_path, {"CRITICAL": 2}, [{"cwe": "CWE-89", "rule_id": "R", "file": "x.py", "line": 1}],
    )
    assert result is None


def test_notify_blocked_skipped_when_on_block_false(tmp_path):
    (tmp_path / "aios-config.json").write_text(json.dumps({
        "notifications": {
            "slack_webhook": "https://x", "on_block": False,
        }
    }))
    result = notify_release_blocked(
        tmp_path, {"CRITICAL": 1}, [],
    )
    assert result is None


def test_notify_blocked_sends_when_configured(tmp_path):
    (tmp_path / "aios-config.json").write_text(json.dumps({
        "notifications": {
            "slack_webhook": "https://hooks.slack.com/x", "on_block": True,
        }
    }))
    fake_resp = MagicMock()
    fake_resp.status = 200
    fake_resp.read.return_value = b"ok"
    fake_resp.__enter__ = lambda self: self
    fake_resp.__exit__ = lambda *a: None
    with patch("aios.core.notifications.urllib.request.urlopen",
               return_value=fake_resp) as m:
        r = notify_release_blocked(
            tmp_path,
            {"CRITICAL": 2, "HIGH": 3},
            [{"cwe": "CWE-89", "rule_id": "R-A", "file": "x.py", "line": 10}],
        )
    assert r is not None and r.sent is True
    # Verifica payload contiene info del finding
    call = m.call_args.args[0]
    body = call.data.decode()
    assert "CRITICAL" in body
    assert "CWE-89" in body


def test_notify_arena_verdict_filters(tmp_path):
    """Solo envia si verdict esta en config.on_arena_verdict."""
    (tmp_path / "aios-config.json").write_text(json.dumps({
        "notifications": {
            "slack_webhook": "https://hooks.slack.com/x",
            "on_arena_verdict": ["NEMESIS_WINS"],
        }
    }))
    # Verdict no en lista · no envia
    r = notify_arena_verdict(tmp_path, "MYTHOS_WINS", "tut-a", 10)
    assert r is None

    # Verdict en lista · envia
    with patch("aios.core.notifications.urllib.request.urlopen") as m:
        fake = MagicMock()
        fake.status = 200
        fake.read.return_value = b"ok"
        fake.__enter__ = lambda s: s
        fake.__exit__ = lambda *a: None
        m.return_value = fake
        r = notify_arena_verdict(tmp_path, "NEMESIS_WINS", "tut-a", 10)
    assert r is not None
    assert r.sent is True
