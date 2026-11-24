"""Tests · catálogo de la organización (org_catalog) con datos ficticios de Acme Corp."""
from __future__ import annotations

from aios.core.org_catalog import (
    ORG_REPOS, SC_PRODUCTS, APP_ANALOGS,
    list_repos, search_repos, get_repo,
    list_sc_products, get_app_mapping,
    fingerprint_repo, suggest_analogs,
)


def test_catalog_has_key_templates():
    """Las plantillas canónicas y el framework del catálogo de servicios están presentes."""
    names = {r.name for r in ORG_REPOS}
    assert "acme-app-template" in names
    assert "acme-monitoring-template" in names
    assert "acme-lambda-authz-template" in names
    assert "acme-service-catalog" in names


def test_catalog_has_all_apps_mapped():
    """Las 8 aplicaciones ficticias tienen mapeo de análogos."""
    names = {m.app for m in APP_ANALOGS}
    expected = {"Billing", "Orders", "Shipping", "FaxGateway", "Partners",
                "Support", "Payments", "Reports"}
    assert expected == names


def test_every_analog_and_product_in_mappings_exists():
    """Integridad referencial: un mapeo sólo apunta a repos y productos del catálogo."""
    repo_names = {r.name for r in ORG_REPOS}
    product_names = {p.name for p in SC_PRODUCTS}
    for m in APP_ANALOGS:
        assert set(m.best_analogs) <= repo_names, m.app
        assert set(m.sc_products_recommended) <= product_names, m.app


def test_list_repos_filter_by_purpose():
    templates = list_repos(purpose="template")
    assert len(templates) >= 6
    assert all(r.purpose == "template" for r in templates)


def test_list_repos_filter_by_language():
    csharp = list_repos(language="c#")
    assert {r.name for r in csharp} == {"acme-legacy-billing"}


def test_list_repos_filter_by_app():
    billing = list_repos(app="Billing")
    # Debe incluir los que tienen Billing en applies_to + los con "*"
    names = {r.name for r in billing}
    assert "acme-legacy-billing" in names
    assert "acme-app-template" in names  # aplica "*"
    assert "acme-legacy-orders" not in names


def test_search_repos_matches_description():
    matches = search_repos("winforms")
    assert [r.name for r in matches] == ["acme-legacy-orders"]


def test_search_repos_matches_name():
    matches = search_repos("eks")
    assert "acme-eks-cicd" in {r.name for r in matches}


def test_get_repo_by_exact_name():
    r = get_repo("acme-app-template")
    assert r is not None
    assert r.purpose == "template"

    assert get_repo("does-not-exist") is None


def test_sc_products_has_infra_and_pipeline_categories():
    all_p = list_sc_products()
    assert len(all_p) >= 18

    infra = list_sc_products(category="infra")
    names = {p.name for p in infra}
    assert "eks-cluster" in names
    assert "container-registry" in names

    pipelines = list_sc_products(category="pipeline")
    pipe_names = {p.name for p in pipelines}
    assert "rest-api-sam-pipeline" in pipe_names


def test_get_app_mapping_billing():
    m = get_app_mapping("Billing")
    assert m is not None
    assert ".NET 8" in m.stack_target
    assert "acme-service-catalog" in m.best_analogs
    assert "eks-cluster" in m.sc_products_recommended


def test_get_app_mapping_case_insensitive():
    m = get_app_mapping("billing")
    assert m is not None
    m2 = get_app_mapping("BILLING")
    assert m.app == m2.app


def test_get_app_mapping_nonexistent():
    assert get_app_mapping("FooBar") is None


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


def test_suggest_analogs_for_csharp_project_returns_legacy_dotnet():
    fp = {"languages": ["C#"], "frameworks": [".NET"], "signals": []}
    analogs = suggest_analogs(fp)
    names = [r.name for r in analogs]
    assert names[0] == "acme-legacy-billing"


def test_suggest_analogs_for_python_cdk_returns_service_catalog():
    fp = {"languages": ["Python"], "frameworks": [],
          "signals": ["AWS CDK project"]}
    analogs = suggest_analogs(fp)
    names = [r.name for r in analogs]
    # El framework del catálogo de servicios debe aparecer alto
    assert any("service-catalog" in n.lower() for n in names[:5])


def test_suggest_analogs_empty_fingerprint_returns_empty():
    fp = {"languages": [], "frameworks": [], "signals": []}
    assert suggest_analogs(fp) == []


def test_fingerprint_handles_missing_path(tmp_path):
    fp = fingerprint_repo(tmp_path / "does-not-exist")
    assert "error" in fp
