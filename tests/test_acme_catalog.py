"""Tests · v3.6.6 · ACME Knowledge Base (amx_catalog)."""
from __future__ import annotations

from pathlib import Path

from aios.core.amx_catalog import (
    AMX_REPOS, SC_PRODUCTS, APLICATIVO_ANALOGS,
    list_repos, search_repos, get_repo,
    list_sc_products, get_aplicativo_mapping,
    fingerprint_repo, suggest_analogs,
)


def test_catalog_has_key_templates():
    """CS-App-Template · CS-Mon-Template · CS_Lambda_AuthZ_Template presentes."""
    names = {r.name for r in AMX_REPOS}
    assert "CS-App-Template" in names
    assert "CS-Mon-Template" in names
    assert "CS_Lambda_AuthZ_Template" in names
    assert "dyn-devops-service-catalog" in names


def test_catalog_has_10_aplicativos_mapped():
    """10 aplicativos eTribe tienen mapping."""
    names = {m.aplicativo for m in APLICATIVO_ANALOGS}
    expected = {"FLEET_OPS_APP", "SRG", "Robot", "NoShow", "CFDIs", "ARC",
                "BSP", "ASR", "Com-Directas", "Com-Indirectas"}
    assert expected.issubset(names)


def test_list_repos_filter_by_purpose():
    templates = list_repos(purpose="template")
    assert len(templates) >= 6
    assert all(r.purpose == "template" for r in templates)


def test_list_repos_filter_by_language():
    csharp = list_repos(language="C#")
    assert len(csharp) >= 2
    assert "RevAcc_Praxis_ASIS_SICOFAV" in {r.name for r in csharp}


def test_list_repos_filter_by_aplicativo():
    fleet_ops_app = list_repos(aplicativo="FLEET_OPS_APP")
    # Debe incluir los que tienen FLEET_OPS_APP en applies_to + los con "*"
    names = {r.name for r in fleet_ops_app}
    assert "RevAcc_Praxis_ASIS_SICOFAV" in names
    assert "CS-App-Template" in names  # aplica "*"


def test_search_repos_matches_description():
    matches = search_repos("SAT")
    assert any("FEBOL" in r.name for r in matches)


def test_search_repos_matches_name():
    matches = search_repos("eks")
    assert len(matches) >= 1  # Miacmeair_EKS_CICD


def test_get_repo_by_exact_name():
    r = get_repo("CS-App-Template")
    assert r is not None
    assert r.purpose == "template"

    assert get_repo("does-not-exist") is None


def test_sc_products_has_eks_and_pipeline_categories():
    all_p = list_sc_products()
    assert len(all_p) >= 18

    infra = list_sc_products(category="infra")
    names = {p.name for p in infra}
    assert "eks_cluster_product" in names
    assert "ecr_product" in names

    pipelines = list_sc_products(category="pipeline")
    pipe_names = {p.name for p in pipelines}
    assert "pipeline_api_gateway_rest_sam_product" in pipe_names


def test_get_aplicativo_mapping_sicofav():
    m = get_aplicativo_mapping("FLEET_OPS_APP")
    assert m is not None
    assert ".NET 8" in m.stack_target
    assert "dyn-devops-service-catalog" in m.best_analogs
    assert "eks_cluster_product" in m.sc_products_recommended


def test_get_aplicativo_mapping_case_insensitive():
    m = get_aplicativo_mapping("fleet_ops_app")
    assert m is not None
    m2 = get_aplicativo_mapping("FLEET_OPS_APP")
    assert m.aplicativo == m2.aplicativo


def test_get_aplicativo_mapping_nonexistent():
    assert get_aplicativo_mapping("FooBar") is None


# ═════════════════════════════════════════════════════════════
# fingerprint_repo · suggest_analogs
# ═════════════════════════════════════════════════════════════

def test_fingerprint_detects_dotnet_project(tmp_path):
    (tmp_path / "App.sln").write_text("dummy")
    (tmp_path / "App.csproj").write_text("<Project/>")
    (tmp_path / "Program.cs").write_text("class P{}")
    (tmp_path / "Other.cs").write_text("class O{}")
    fp = fingerprint_repo(tmp_path)
    assert "C#" in fp["languages"]
    assert ".NET" in fp["frameworks"]


def test_fingerprint_detects_angular_project(tmp_path):
    (tmp_path / "angular.json").write_text("{}")
    (tmp_path / "package.json").write_text('{"name":"x"}')
    (tmp_path / "app.ts").write_text("export class A {}")
    (tmp_path / "other.ts").write_text("export class B {}")
    fp = fingerprint_repo(tmp_path)
    assert "TypeScript" in fp["languages"]
    assert "Angular" in fp["frameworks"]
    assert any("Angular" in s for s in fp["signals"])


def test_fingerprint_detects_cdk_project(tmp_path):
    (tmp_path / "cdk.json").write_text("{}")
    (tmp_path / "app.py").write_text("import aws_cdk")
    (tmp_path / "stack.py").write_text("class S: pass")
    fp = fingerprint_repo(tmp_path)
    assert "Python" in fp["languages"]
    assert any("CDK" in s for s in fp["signals"])


def test_suggest_analogs_for_csharp_project_returns_revacc():
    fp = {"languages": ["C#"], "frameworks": [".NET"], "signals": []}
    analogs = suggest_analogs(fp)
    names = [r.name for r in analogs]
    assert any("RevAcc_Praxis_ASIS_SICOFAV" in n for n in names)


def test_suggest_analogs_for_python_cdk_returns_service_catalog():
    fp = {"languages": ["Python"], "frameworks": [],
          "signals": ["AWS CDK project"]}
    analogs = suggest_analogs(fp)
    names = [r.name for r in analogs]
    # El service catalog framework debe aparecer alto
    assert any("service-catalog" in n.lower() for n in names[:5])


def test_suggest_analogs_empty_fingerprint_returns_empty():
    fp = {"languages": [], "frameworks": [], "signals": []}
    assert suggest_analogs(fp) == []


def test_fingerprint_handles_missing_path(tmp_path):
    fp = fingerprint_repo(tmp_path / "does-not-exist")
    assert "error" in fp
