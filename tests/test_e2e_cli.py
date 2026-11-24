"""E2E de la CLI: se ejecuta `python -m aios.cli.main` como proceso externo en un proyecto temporal y se
afirman el código de salida, la salida y los archivos que deja. Sin red ni credenciales."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


def aios(proyecto: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "aios.cli.main", *args],
        cwd=proyecto, capture_output=True, text=True, timeout=120,
    )


@pytest.fixture
def proyecto(tmp_path: Path) -> Path:
    return tmp_path


def test_governance_request_audit_and_escalate_flow(proyecto):
    r = aios(proyecto, "governance", "request", "--type", "bd-access", "--app", "billing",
             "--format", "md", "--output", "req", "--audit-root", ".")
    assert r.returncode == 0, r.stderr
    [md] = list((proyecto / "req").glob("GOV-BILLING-BD-*.md"))
    assert "Billing" in md.read_text(encoding="utf-8")

    r = aios(proyecto, "governance", "audit", "--app", "billing", "--audit-root", ".", "--update",
             "--status", "in-review", "--signer", "pmo@acme.example", "--actor-role", "pm")
    assert r.returncode == 0, r.stdout + r.stderr

    # Transición inválida (in-review → provisioned): rechazada y con código de salida distinto de 0
    r = aios(proyecto, "governance", "audit", "--app", "billing", "--audit-root", ".", "--update",
             "--status", "provisioned", "--signer", "x@acme.example")
    assert r.returncode == 1
    assert "Transición rechazada" in r.stdout + r.stderr

    r = aios(proyecto, "governance", "audit", "--app", "billing", "--audit-root", ".")
    assert r.returncode == 0
    assert "in-review" in r.stdout

    # Contrato documentado: 1 = nada que escalar (un cron distingue «se envió» de «no hubo atraso»)
    r = aios(proyecto, "governance", "escalate", "--app", "billing", "--audit-root", ".", "--json")
    assert r.returncode == 1
    assert json.loads(r.stdout)["status"] == "no_slippage"

    trail = proyecto / ".aios" / "governance" / "audit-trail.jsonl"
    assert len(trail.read_text(encoding="utf-8").splitlines()) == 2   # solicitud + firma válida


def test_unknown_app_fails_with_nonzero_exit(proyecto):
    r = aios(proyecto, "governance", "request", "--type", "bd-access", "--app", "no-existe",
             "--format", "md", "--output", "req", "--audit-root", ".")
    assert r.returncode == 2
    assert not (proyecto / "req").exists()


def test_tier_classify_explains_the_criteria(proyecto):
    r = aios(proyecto, "tier", "classify", "--app", "partners", "--explain")
    assert r.returncode == 0
    assert "declared=T2" in r.stdout and "PCI / PII" in r.stdout


def test_release_blocks_a_project_with_a_critical_finding(proyecto):
    (proyecto / "app.py").write_text("import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n")
    r = aios(proyecto, "release", "--root", ".")
    assert r.returncode == 1
    assert "STATIC-CMD-SHELL-TRUE" in r.stdout
    assert "Ready for release: NO" in r.stdout
