"""v3.7.0 · tests discovery-generate · genera 9 docs Fase 1."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aios.core.discovery.generate import (
    generate_discovery_docs,
    build_doc_01_code_scan, build_doc_02_hallazgos_mapped,
    build_doc_03_arq_as_is, build_doc_04_stakeholders,
    build_doc_05_vulns, build_doc_06_deps,
    build_doc_07_preguntas_nuevas, build_doc_08_bloqueadores,
    build_doc_09_risk_register,
)
from aios.core.discovery.helpers import resolve_app
from aios.core.plan_v5 import APPS


EMPTY_SCAN = {"findings": [], "count": 0, "by_severity": {}, "by_cwe": {}, "error": None}


def test_resolve_app_valid():
    app = resolve_app("sicofav")
    assert app.short == "SICOFAV"
    assert app.tier == "T0"


def test_resolve_app_invalid_raises():
    with pytest.raises(ValueError, match="no encontrado"):
        resolve_app("does-not-exist")


def test_resolve_app_case_insensitive():
    app = resolve_app("SICOFAV")
    assert app.short == "SICOFAV"


def test_doc_01_contains_severity_table():
    app = resolve_app("sicofav")
    scan = {"findings": [], "count": 5, "by_severity": {"HIGH": 3, "LOW": 2},
            "by_cwe": {"CWE-22": 2}, "error": None}
    md = build_doc_01_code_scan(app, scan)
    assert "# 01 · Code Scan · SICOFAV" in md
    assert "| HIGH | 3 |" in md or "HIGH | 3" in md
    assert "CWE-22" in md


def test_doc_01_with_scan_error():
    app = resolve_app("arc")
    scan = {"findings": [], "count": 0, "by_severity": {}, "by_cwe": {},
            "error": "no repo"}
    md = build_doc_01_code_scan(app, scan)
    assert "Scan error" in md
    assert "no repo" in md


def test_doc_02_includes_cwe_mapping():
    app = resolve_app("sicofav")

    # Fake findings con CWE
    class FakeFinding:
        def __init__(self, cwe, sev):
            self.cwe = cwe
            self.severity = sev

    scan = {
        "findings": [FakeFinding("CWE-798", "HIGH"),
                     FakeFinding("CWE-798", "HIGH"),
                     FakeFinding("CWE-22", "MEDIUM")],
        "count": 3,
        "by_severity": {"HIGH": 2, "MEDIUM": 1},
        "by_cwe": {"CWE-798": 2, "CWE-22": 1},
        "error": None,
    }
    md = build_doc_02_hallazgos_mapped(app, scan)
    assert "CWE-798" in md
    assert "CWE-22" in md


def test_doc_03_with_empty_stack():
    app = resolve_app("arc")
    md = build_doc_03_arq_as_is(app, {})
    assert "skeleton" in md.lower() or "sin stack" in md.lower()


def test_doc_03_with_detected_stack():
    app = resolve_app("sicofav")
    stack = {"dotnet": ["src/Foo.csproj"], "docker": ["Dockerfile"]}
    md = build_doc_03_arq_as_is(app, stack)
    assert "dotnet" in md
    assert "Foo.csproj" in md


def test_doc_04_has_governance_contacts():
    app = resolve_app("sicofav")
    md = build_doc_04_stakeholders(app)
    assert "Antonio Hernández" in md
    assert "Miguel Rachid" in md
    assert "Diego Zarate" in md


def test_doc_05_vulns_compliance_rows():
    app = resolve_app("sicofav")
    md = build_doc_05_vulns(app, EMPTY_SCAN)
    assert "LFPDPPP" in md
    assert "SOX" in md
    assert "OWASP" in md


def test_doc_05_t0_is_sox_critical():
    app = resolve_app("sicofav")  # T0
    md = build_doc_05_vulns(app, EMPTY_SCAN)
    # T0 debe tener SOX como "Sí"
    assert "SOX" in md and "✅ Sí" in md


def test_doc_06_deps_lists_lockfile_by_stack():
    app = resolve_app("sicofav")
    md = build_doc_06_deps(app, {"dotnet": ["foo.csproj"], "node": ["package.json"]})
    assert "dotnet" in md
    assert "node" in md


def test_doc_07_preguntas_6_categorias():
    app = resolve_app("sicofav")
    md = build_doc_07_preguntas_nuevas(app)
    for cat in ["Arquitectura", "Datos", "Integraciones",
                "Seguridad", "Operación", "Negocio"]:
        assert cat in md


def test_doc_08_cross_app_blockers_present():
    app = resolve_app("sicofav")
    md = build_doc_08_bloqueadores(app)
    assert "Cross-app blockers" in md
    assert "KMS" in md or "kms" in md.lower()


def test_doc_09_risk_register_tier_aware():
    app_t0 = resolve_app("sicofav")  # T0
    md_t0 = build_doc_09_risk_register(app_t0, EMPTY_SCAN)
    assert "SOX" in md_t0

    app_t3 = next((a for a in APPS.values() if a.tier == "T3"), None)
    if app_t3 is not None:
        md_t3 = build_doc_09_risk_register(app_t3, EMPTY_SCAN)
        assert "Obsolescencia" in md_t3 or "R-01" in md_t3


def test_doc_09_aios_findings_impact():
    app = resolve_app("sicofav")
    scan = {"findings": [], "count": 0,
            "by_severity": {"CRITICAL": 2, "HIGH": 5},
            "by_cwe": {}, "error": None}
    md = build_doc_09_risk_register(app, scan)
    assert "R-AIOS-C" in md
    assert "R-AIOS-H" in md


def test_generate_discovery_docs_creates_9(tmp_path: Path):
    result = generate_discovery_docs("sicofav", tmp_path)
    assert result["app"] == "SICOFAV"
    assert result["tier"] == "T0"
    assert len(result["docs"]) == 9

    out_dir = Path(result["out_dir"])
    for num in ["01", "02", "03", "04", "05", "06", "07", "08", "09"]:
        files = list(out_dir.glob(f"{num}_*.md"))
        assert len(files) == 1, f"Missing doc {num}"


def test_generate_skips_existing_without_overwrite(tmp_path: Path):
    r1 = generate_discovery_docs("sicofav", tmp_path)
    r2 = generate_discovery_docs("sicofav", tmp_path)  # sin overwrite
    skipped = [d for d in r2["docs"] if d["status"] == "skipped-exists"]
    assert len(skipped) == 9


def test_generate_overwrite_true_rewrites(tmp_path: Path):
    generate_discovery_docs("sicofav", tmp_path)
    r2 = generate_discovery_docs("sicofav", tmp_path, overwrite=True)
    written = [d for d in r2["docs"] if d["status"] == "written"]
    assert len(written) == 9


def test_generate_invalid_app_raises(tmp_path: Path):
    with pytest.raises(ValueError):
        generate_discovery_docs("no-existe", tmp_path)
