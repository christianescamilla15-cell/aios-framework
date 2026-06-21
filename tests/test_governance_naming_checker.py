"""Tests · governance.checkers.naming · 4 detectores ACME (IAM·CMK·Secret·KMS-AWS)."""

from __future__ import annotations

from pathlib import Path

import pytest

from aios.governance.checkers.naming import NamingChecker, _iter_files, EXCLUDED_DIRS
from aios.governance.loader import load_rules, reset_cache
from aios.governance.models import CheckSeverity


@pytest.fixture(autouse=True)
def _reset_loader_cache():
    reset_cache()
    yield
    reset_cache()


@pytest.fixture
def checker():
    return NamingChecker(load_rules())


# ── _iter_files · poda EXCLUDED_DIRS ─────────────────────────────────


def test_iter_files_skips_excluded_dirs(tmp_path):
    """node_modules · .venv · cdk.out NO deben ser recorridos."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("# OK")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.py").write_text("# JUNK")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "site.py").write_text("# JUNK")

    files = list(_iter_files(tmp_path, ["**/*.py"]))
    rels = {f.relative_to(tmp_path).as_posix() for f in files}
    assert "src/main.py" in rels
    assert "node_modules/junk.py" not in rels
    assert ".venv/site.py" not in rels


def test_excluded_dirs_includes_critical_paths():
    """Sanity · EXCLUDED_DIRS debe contener los típicos sospechosos."""
    for d in ("node_modules", ".venv", "cdk.out", "__pycache__", "TestResults", ".git"):
        assert d in EXCLUDED_DIRS


# ── G-NEW-IAM-NAMING-FULL ────────────────────────────────────────────


def test_iam_role_naming_passes_for_compliant_name(tmp_path, checker):
    (tmp_path / "stack.py").write_text(
        'role_name = "ACME-R-FLEET_OPS_APP-A"\nother = "ACME-R-NOSHOW-DES"\n'
    )
    findings = checker.check(tmp_path, app="fleet_ops_app")
    iam = [f for f in findings if f.rule_id == "G-NEW-IAM-NAMING-FULL"]
    assert iam == []


def test_iam_role_naming_fails_for_non_compliant_suffix(tmp_path, checker):
    """ACME-R-X-FOO NO sigue {A|DES|SL}."""
    (tmp_path / "stack.py").write_text('role = "ACME-R-FLEET_OPS_APP-INVALID"\n')
    findings = checker.check(tmp_path, app="fleet_ops_app")
    iam = [f for f in findings if f.rule_id == "G-NEW-IAM-NAMING-FULL"]
    assert len(iam) == 1
    assert iam[0].severity == CheckSeverity.FAIL
    assert "ACME-R-FLEET_OPS_APP-INVALID" in iam[0].message


# ── G-NEW-CMK-NAMING ─────────────────────────────────────────────────


def test_cmk_naming_passes_for_compliant_alias(tmp_path, checker):
    """FILE_GLOBS['cmk'] cubre .ts/.tf/.yaml — usamos .tf para portabilidad."""
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_alias" "x" { name = "alias/acme-kms-fleet_ops_app-secrets" }\n'
    )
    findings = checker.check(tmp_path, app="fleet_ops_app")
    cmk = [f for f in findings if f.rule_id == "G-NEW-CMK-NAMING"]
    assert cmk == []


def test_cmk_naming_fails_for_unknown_scope(tmp_path, checker):
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_alias" "x" { name = "alias/acme-kms-fleet_ops_app-CUSTOMSCOPE" }\n'
    )
    findings = checker.check(tmp_path, app="fleet_ops_app")
    cmk = [f for f in findings if f.rule_id == "G-NEW-CMK-NAMING"]
    assert len(cmk) >= 1
    assert cmk[0].severity == CheckSeverity.WARN


# ── G-CDK-KMS-AWS-MANAGED-PROHIBITION (CRITICAL) ─────────────────────


def test_kms_aws_managed_alias_flags_critical(tmp_path, checker):
    """Usar alias/aws/s3 = CRITICAL · prohibido por ACME."""
    (tmp_path / "infra.tf").write_text(
        'resource "x" { kms_key_id = "alias/aws/s3" }\n'
    )
    findings = checker.check(tmp_path, app="fleet_ops_app")
    kms = [f for f in findings if f.rule_id == "G-CDK-KMS-AWS-MANAGED-PROHIBITION"]
    assert len(kms) == 1
    assert kms[0].severity == CheckSeverity.CRITICAL


def test_kms_customer_managed_alias_passes(tmp_path, checker):
    (tmp_path / "infra.tf").write_text(
        'resource "x" { kms_key_id = "alias/acme-kms-fleet_ops_app-aurora" }\n'
    )
    findings = checker.check(tmp_path, app="fleet_ops_app")
    kms = [f for f in findings if f.rule_id == "G-CDK-KMS-AWS-MANAGED-PROHIBITION"]
    assert kms == []


# ── G-NEW-SECRET-NAMING ──────────────────────────────────────────────


def test_secret_naming_compliant_passes(tmp_path, checker):
    (tmp_path / "config.py").write_text(
        'secret = "acme/01-fleet_ops_app/db"\n'
    )
    findings = checker.check(tmp_path, app="fleet_ops_app")
    sec = [f for f in findings if f.rule_id == "G-NEW-SECRET-NAMING"]
    assert sec == []


def test_secret_naming_fails_for_missing_app_id(tmp_path, checker):
    """acme/fleet_ops_app/db sin ## prefix · NO compliant."""
    (tmp_path / "config.py").write_text(
        'secret = "acme/fleet_ops_app/db"\n'
    )
    findings = checker.check(tmp_path, app="fleet_ops_app")
    sec = [f for f in findings if f.rule_id == "G-NEW-SECRET-NAMING"]
    assert len(sec) >= 1


# ── Integración E2E · clean repo ─────────────────────────────────────


def test_clean_repo_produces_zero_findings(tmp_path, checker):
    (tmp_path / "main.py").write_text(
        '# pure logic\ndef sum(a, b): return a + b\n'
    )
    findings = checker.check(tmp_path, app="fleet_ops_app")
    assert findings == []
