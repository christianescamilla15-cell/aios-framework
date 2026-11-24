"""Reglas de los analizadores de apoyo: ontología de dominio, drift entre copias, exfiltración y PII
en datos de ejecución. Datos inventados."""
from __future__ import annotations

from pathlib import Path

import pytest

from aios.core.ontology import (
    ACTION_AUTO_FIX,
    ACTION_PAUSE_FOR_REVIEW,
    ACTION_SKIP,
    classify_finding,
    load_ontology,
)

EJEMPLO = Path(__file__).resolve().parents[1] / "docs" / "ejemplos" / "domain-ontology.example.yaml"


@pytest.fixture(scope="module")
def ontologia():
    o = load_ontology(EJEMPLO)
    assert o["patterns"], "la ontología de ejemplo debe cargar"
    return o


# ── Ontología de dominio ──────────────────────────────────────────────

def test_bug_with_auto_fix_allowed_is_auto_fixed(ontologia):
    r = classify_finding({"rule_id": "X", "snippet": 'password = "Fict1cia"', "file": "app.py"}, ontologia)
    assert (r.classification, r.action, r.ontology_match) == ("bug", ACTION_AUTO_FIX, "CWE_798_CREDENTIAL_PLAINTEXT")


def test_business_rule_pauses_for_review_with_its_message(ontologia):
    r = classify_finding({"rule_id": "X", "snippet": "promo.maxDiscountPercent = 35", "file": "promo.cs"}, ontologia)
    assert r.classification == "business_rule"
    assert r.action == ACTION_PAUSE_FOR_REVIEW
    assert "Ventas" in r.message
    assert r.evidence_required == ["acuerdo comercial vigente"]


def test_multi_match_ranks_bug_over_migration_and_keeps_the_rest(ontologia):
    snippet = 'password = "LegacyAcct01"'
    r = classify_finding({"rule_id": "X", "snippet": snippet, "file": "app.config"}, ontologia)
    assert r.classification == "bug"
    assert r.additional_matches == ["LEGACY_SERVICE_ACCOUNT"]
    assert set(r.tags) == {"credenciales", "heredado"}


def test_skip_pattern_by_path(ontologia):
    r = classify_finding({"rule_id": "X", "snippet": "x = 1", "file": "tests/fixtures/sample.py"}, ontologia)
    assert r.action == ACTION_SKIP


def test_no_match_falls_back_to_safe_default(ontologia):
    r = classify_finding({"rule_id": "X", "snippet": "total = a + b", "file": "calc.py"}, ontologia)
    assert r.ontology_match is None
    assert r.classification == "unclear"
    assert r.action == ACTION_PAUSE_FOR_REVIEW


def test_missing_ontology_keeps_backwards_compatible_auto_fix(tmp_path):
    o = load_ontology(tmp_path / "no-existe.yaml")
    r = classify_finding({"rule_id": "X", "snippet": "x", "file": "a.py"}, o)
    assert r.action == ACTION_AUTO_FIX


# ── Drift entre copias por ambiente ───────────────────────────────────

def _config(raiz: Path, nombre: str, password: str) -> None:
    raiz.mkdir(parents=True, exist_ok=True)
    (raiz / nombre).write_text(
        '<configuration><appSettings>'
        f'<add key="DbPassword" value="{password}"/>'
        '</appSettings></configuration>\n',
        encoding="utf-8",
    )


def _credenciales(report):
    return [(f.severity, f.key) for f in report.findings if f.kind == "credential_byte_identity"]


def test_same_credential_in_qa_and_prod_files_is_critical(tmp_path):
    """Regla: misma credencial en un archivo de QA/test/staging y otro de producción → CRITICAL."""
    from aios.core.drift_detector import detect_drift

    _config(tmp_path / "a", "Web.qa.config", "Demo-Clave-1")
    _config(tmp_path / "b", "Web.prod.config", "Demo-Clave-1")
    report = detect_drift(tmp_path / "a", tmp_path / "b")
    assert _credenciales(report) == [("CRITICAL", "DbPassword")]
    assert all("Demo-Clave-1" not in f.value_a + f.value_b + f.message for f in report.findings)


def test_same_credential_without_environment_in_name_is_high(tmp_path):
    """Sin ambiente en el nombre del archivo la duplicación se reporta HIGH (no se puede afirmar cruce)."""
    from aios.core.drift_detector import detect_drift

    _config(tmp_path / "qa", "Web.config", "Demo-Clave-1")
    _config(tmp_path / "prod", "Web.config", "Demo-Clave-1")
    assert _credenciales(detect_drift(tmp_path / "qa", tmp_path / "prod")) == [("HIGH", "DbPassword")]


def test_different_credentials_are_not_reported(tmp_path):
    from aios.core.drift_detector import detect_drift

    _config(tmp_path / "a", "Web.qa.config", "Demo-Clave-1")
    _config(tmp_path / "b", "Web.prod.config", "Demo-Clave-2")
    assert _credenciales(detect_drift(tmp_path / "a", tmp_path / "b")) == []


def test_references_to_a_secret_store_are_not_credentials(tmp_path):
    from aios.core.drift_detector import detect_drift

    ref = "${ssm:/billing/db}"
    _config(tmp_path / "a", "Web.qa.config", ref)
    _config(tmp_path / "b", "Web.prod.config", ref)
    assert _credenciales(detect_drift(tmp_path / "a", tmp_path / "b")) == []


# ── Exfiltración hacia dominios no corporativos ───────────────────────

def test_external_recipient_severity_depends_on_environment(tmp_path):
    from aios.core.exfil_detector import detect_exfil

    (tmp_path / "config").mkdir()
    (tmp_path / "tests").mkdir()
    linea = '{"alerts": "ops@proveedor-externo.com"}\n'
    (tmp_path / "config" / "appsettings.Production.json").write_text(linea)
    (tmp_path / "tests" / "appsettings.json").write_text(linea)
    (tmp_path / "config" / "appsettings.json").write_text(linea)
    por_archivo = {
        Path(f.file).relative_to(tmp_path).as_posix(): f.severity
        for f in detect_exfil(tmp_path, corporate_domains=["acme-corp.com"]).findings
    }
    assert por_archivo == {
        "config/appsettings.Production.json": "HIGH",
        "tests/appsettings.json": "INFO",
        "config/appsettings.json": "MEDIUM",
    }


def test_corporate_and_subdomains_are_not_exfil(tmp_path):
    from aios.core.exfil_detector import detect_exfil

    (tmp_path / "appsettings.Production.json").write_text(
        '{"a": "ops@acme-corp.com", "b": "noc@mx.acme-corp.com"}\n'
    )
    assert detect_exfil(tmp_path, corporate_domains=["acme-corp.com"]).findings == []


# ── PII en datos de ejecución ─────────────────────────────────────────

@pytest.mark.parametrize("linea,tipo", [
    ("cobro tarjeta 4111 1111 1111 1111 aprobado", "pan"),       # Luhn válido
    ("booking ABC123 confirmado", "record_locator"),              # con palabra clave
])
def test_runtime_data_detects(tmp_path, linea, tipo):
    from aios.core.runtime_data_scanner import scan_runtime_data

    (tmp_path / "export.log").write_text(linea + "\n")
    assert tipo in {f.kind for f in scan_runtime_data(tmp_path).findings}


@pytest.mark.parametrize("linea,tipo", [
    ("cobro tarjeta 4111 1111 1111 1112 aprobado", "pan"),       # Luhn inválido
    ("lote ABC123 procesado", "record_locator"),                  # sin palabra clave
])
def test_runtime_data_ignores(tmp_path, linea, tipo):
    from aios.core.runtime_data_scanner import scan_runtime_data

    (tmp_path / "export.log").write_text(linea + "\n")
    assert tipo not in {f.kind for f in scan_runtime_data(tmp_path).findings}


def test_runtime_data_redacts_the_card_number(tmp_path):
    from aios.core.runtime_data_scanner import scan_runtime_data

    (tmp_path / "export.log").write_text("cobro tarjeta 4111 1111 1111 1111 aprobado\n")
    pan = [f for f in scan_runtime_data(tmp_path).findings if f.kind == "pan"][0]
    assert "4111111111111111" not in pan.sample
    assert pan.severity == "HIGH"


# ── Revisión humana (stakeholder in the loop) ─────────────────────────

def _decision(fid: str, action: str, ts: str):
    from aios.core.review import ReviewDecision

    return ReviewDecision(timestamp=ts, finding_id=fid, file="promo.cs", line=47,
                          rule_id="FORBIDDEN-LITERAL-35", action=action, reason="prueba")


def test_finding_id_is_deterministic_and_location_sensitive():
    from aios.core.review import make_finding_id

    a = make_finding_id("promo.cs", 47, "R")
    assert a == make_finding_id("promo.cs", 47, "R")
    assert a.startswith("FRK-") and len(a) == 14
    assert a != make_finding_id("promo.cs", 48, "R")


def test_decisions_split_findings_and_the_latest_one_wins(tmp_path):
    from aios.core.review import filter_findings_by_decisions, log_decision, make_finding_id

    fid = make_finding_id("promo.cs", 47, "FORBIDDEN-LITERAL-35")
    hallazgo = {"file": "promo.cs", "line": 47, "rule_id": "FORBIDDEN-LITERAL-35"}
    otro = {"file": "otro.cs", "line": 1, "rule_id": "X"}

    assert [f["rule_id"] for f in filter_findings_by_decisions([hallazgo, otro], tmp_path)["pending"]] == \
        ["FORBIDDEN-LITERAL-35", "X"]

    log_decision(tmp_path, _decision(fid, "reject", "2026-11-01T10:00:00Z"))
    assert len(filter_findings_by_decisions([hallazgo], tmp_path)["rejected"]) == 1

    log_decision(tmp_path, _decision(fid, "approve", "2026-11-02T10:00:00Z"))
    buckets = filter_findings_by_decisions([hallazgo, otro], tmp_path)
    assert [f["finding_id"] for f in buckets["approved"]] == [fid]
    assert buckets["rejected"] == []
    assert [f["rule_id"] for f in buckets["pending"]] == ["X"]


def test_unknown_action_is_treated_as_pending(tmp_path):
    from aios.core.review import filter_findings_by_decisions, log_decision, make_finding_id

    fid = make_finding_id("promo.cs", 47, "FORBIDDEN-LITERAL-35")
    log_decision(tmp_path, _decision(fid, "maybe", "2026-11-01T10:00:00Z"))
    hallazgo = {"file": "promo.cs", "line": 47, "rule_id": "FORBIDDEN-LITERAL-35"}
    assert len(filter_findings_by_decisions([hallazgo], tmp_path)["pending"]) == 1
