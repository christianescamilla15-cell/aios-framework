"""Tests · governance.checkers.naming · 4 detectores (rol IAM · llave KMS · secreto · KMS de AWS)."""

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


# ── G-IAM-ROLE-NAMING ────────────────────────────────────────────────


def test_iam_role_naming_passes_for_compliant_name(tmp_path, checker):
    (tmp_path / "stack.py").write_text(
        'role_name = "acme-role-billing-admin"\nother = "acme-role-reports-readonly"\n'
    )
    findings = checker.check(tmp_path, app="billing")
    iam = [f for f in findings if f.rule_id == "G-IAM-ROLE-NAMING"]
    assert iam == []


def test_iam_role_naming_fails_for_non_compliant_suffix(tmp_path, checker):
    """acme-role-X-owner NO sigue {admin|dev|readonly}."""
    (tmp_path / "stack.py").write_text('role = "acme-role-billing-owner"\n')
    findings = checker.check(tmp_path, app="billing")
    iam = [f for f in findings if f.rule_id == "G-IAM-ROLE-NAMING"]
    assert len(iam) == 1
    assert iam[0].severity == CheckSeverity.FAIL
    assert "acme-role-billing-owner" in iam[0].message
    assert iam[0].location == "stack.py:1"


def test_iam_role_naming_flags_uppercase_variant(tmp_path, checker):
    """El candidato se busca sin distinguir mayúsculas; el patrón exige minúsculas."""
    (tmp_path / "roles.tf").write_text('name = "ACME-ROLE-BILLING-ADMIN"\n')
    findings = checker.check(tmp_path, app="billing")
    assert [f.rule_id for f in findings] == ["G-IAM-ROLE-NAMING"]


def test_iam_role_naming_skips_reserved_service_prefix(tmp_path, checker):
    """acme-role-svc-* lo crea la plataforma con nombre propio · no se marca."""
    (tmp_path / "stack.py").write_text('role = "acme-role-svc-log-shipper"\n')
    findings = checker.check(tmp_path, app="billing")
    assert [f for f in findings if f.rule_id == "G-IAM-ROLE-NAMING"] == []


# ── G-CMK-NAMING ─────────────────────────────────────────────────────


def test_cmk_naming_passes_for_compliant_alias(tmp_path, checker):
    """FILE_GLOBS['cmk'] cubre .ts/.tf/.yaml — usamos .tf para portabilidad."""
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_alias" "x" { name = "alias/acme-kms-billing-secrets" }\n'
    )
    findings = checker.check(tmp_path, app="billing")
    cmk = [f for f in findings if f.rule_id == "G-CMK-NAMING"]
    assert cmk == []


def test_cmk_naming_fails_for_unknown_scope(tmp_path, checker):
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_alias" "x" { name = "alias/acme-kms-billing-CUSTOMSCOPE" }\n'
    )
    findings = checker.check(tmp_path, app="billing")
    cmk = [f for f in findings if f.rule_id == "G-CMK-NAMING"]
    assert len(cmk) >= 1
    assert cmk[0].severity == CheckSeverity.WARN


def test_cmk_naming_ignores_third_party_aliases(tmp_path, checker):
    """Sólo se revisan alias con el prefijo propio acme-kms-."""
    (tmp_path / "kms.tf").write_text('name = "alias/vendor-key-01"\n')
    findings = checker.check(tmp_path, app="billing")
    assert [f for f in findings if f.rule_id == "G-CMK-NAMING"] == []


# ── G-KMS-AWS-MANAGED-PROHIBITED (CRITICAL) ──────────────────────────


def test_kms_aws_managed_alias_flags_critical(tmp_path, checker):
    """Usar alias/aws/s3 = CRITICAL · no admite política ni rotación propias."""
    (tmp_path / "infra.tf").write_text(
        'resource "x" { kms_key_id = "alias/aws/s3" }\n'
    )
    findings = checker.check(tmp_path, app="billing")
    kms = [f for f in findings if f.rule_id == "G-KMS-AWS-MANAGED-PROHIBITED"]
    assert len(kms) == 1
    assert kms[0].severity == CheckSeverity.CRITICAL


def test_kms_customer_managed_alias_passes(tmp_path, checker):
    (tmp_path / "infra.tf").write_text(
        'resource "x" { kms_key_id = "alias/acme-kms-billing-database" }\n'
    )
    findings = checker.check(tmp_path, app="billing")
    kms = [f for f in findings if f.rule_id == "G-KMS-AWS-MANAGED-PROHIBITED"]
    assert kms == []


# ── G-SECRET-NAMING ──────────────────────────────────────────────────


def test_secret_naming_compliant_passes(tmp_path, checker):
    (tmp_path / "config.py").write_text(
        'secret = "acme/billing/db"\n'
    )
    findings = checker.check(tmp_path, app="billing")
    sec = [f for f in findings if f.rule_id == "G-SECRET-NAMING"]
    assert sec == []


def test_secret_naming_fails_for_missing_app(tmp_path, checker):
    """acme/db sin el segmento de la app · NO cumple."""
    (tmp_path / "config.py").write_text(
        'secret = "acme/db"\n'
    )
    findings = checker.check(tmp_path, app="billing")
    sec = [f for f in findings if f.rule_id == "G-SECRET-NAMING"]
    assert len(sec) >= 1


def test_secret_naming_fails_for_underscore(tmp_path, checker):
    (tmp_path / "config.py").write_text('secret = "acme/billing/db_password"\n')
    findings = checker.check(tmp_path, app="billing")
    assert [f.rule_id for f in findings] == ["G-SECRET-NAMING"]


# ── Integración E2E · clean repo ─────────────────────────────────────


def test_clean_repo_produces_zero_findings(tmp_path, checker):
    (tmp_path / "main.py").write_text(
        '# pure logic\ndef sum(a, b): return a + b\n'
    )
    findings = checker.check(tmp_path, app="billing")
    assert findings == []


def test_examples_in_naming_yaml_are_self_consistent():
    """Los ejemplos válidos/ inválidos documentados en naming.yaml cumplen/ no cumplen su propio regex."""
    import re

    rules = load_rules()
    for kind in ("iam_role_naming", "repo_naming", "cmk_naming", "secret_naming"):
        rule = rules.get_naming_pattern(kind)
        pattern = re.compile(rule["pattern_regex"])
        reserved = tuple(r["prefix"] for r in rule.get("reserved_prefixes", []))
        for ok in rule.get("examples_valid", []):
            assert pattern.match(ok) or (reserved and ok.startswith(reserved)), (kind, ok)
        for bad in rule.get("examples_invalid", []):
            assert not pattern.match(bad), (kind, bad)
