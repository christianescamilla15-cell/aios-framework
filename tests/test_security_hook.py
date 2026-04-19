"""Tests · security pre-commit hook · template + install."""

from __future__ import annotations

from pathlib import Path

import pytest

from aios.core.hooks import HOOK_TEMPLATES, install_git_hook


def test_security_hook_template_registered():
    assert "security" in HOOK_TEMPLATES
    tpl = HOOK_TEMPLATES["security"]
    assert "security_gate" in tpl["description"] or "Security" in tpl["description"]
    assert tpl["script"].startswith("#!/bin/sh")


def test_security_hook_script_has_expected_commands():
    script = HOOK_TEMPLATES["security"]["script"]
    # v2 · hook invoca security-scan-staged con stdin · mas rapido que
    # el scan completo previo.
    assert "aios security-scan-staged" in script
    assert "git diff --cached --name-only" in script
    assert "--no-verify" in script
    assert "CRITICAL" in script


def test_install_security_hook_creates_file(tmp_path):
    # Fake git repo
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    ok = install_git_hook(tmp_path, "security")
    assert ok
    hook = tmp_path / ".git" / "hooks" / "pre-commit"
    assert hook.exists()
    content = hook.read_text()
    assert "aios security-scan-staged" in content
    # Verifica ejecutable bit
    if hasattr(hook, "stat"):
        import stat
        assert hook.stat().st_mode & stat.S_IXUSR


def test_install_security_fails_without_git_dir(tmp_path):
    # Sin .git/hooks · install debe retornar False
    ok = install_git_hook(tmp_path, "security")
    assert ok is False


def test_install_unknown_hook_returns_false(tmp_path):
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    ok = install_git_hook(tmp_path, "xyz-does-not-exist")
    assert ok is False


def test_security_hook_does_not_overwrite_other_templates():
    """Regression guard · agregar 'security' no rompe otros templates."""
    for name in ("pre-commit", "secrets-only", "post-save-tests", "security"):
        assert name in HOOK_TEMPLATES
