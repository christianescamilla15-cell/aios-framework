"""v3.6.6 · ACME Knowledge Base · BO-ACME org catalog + Service Catalog products.

Registry estructurado de los 95 repos accesibles en BO-ACME (via acme-team
SSO) + 20+ productos del Service Catalog (`dyn-devops-service-catalog`) + 6
templates canónicos CS-* · para que AIOS pueda:

1. Sugerir análogos cuando un aplicativo del scope eTribe arranca refactor
2. Listar productos Service Catalog para Block 8 infra
3. Identificar templates que se deben consumir en vez de reinventar

Fuente de verdad:
- Inventario 2026-04-24 · `gh repo list BO-ACME --limit 500 --json`
- Clones locales en `_analogos/` + `_templates/` + `_references/`
- Documento `ANALOGOS_BO-AMX_vs_10APPS_24abr.md` (reporte ejecutivo)

Refresh: manual via `aios acme-catalog refresh` (v3.6.7 · pending) o
actualizando las constantes en este archivo cuando se cumple TTL de 90 días.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# Último refresh de datos · YYYY-MM-DD
CATALOG_LAST_REFRESHED = "2026-04-24"

# TTL recomendado antes de refresh manual (días)
CATALOG_TTL_DAYS = 90


@dataclass(frozen=True)
class AmxRepo:
    """Un repo de BO-ACME con metadata relevante."""
    name: str
    language: Optional[str]   # C#, VB.NET, Python, Shell, Java, JS, None
    description: str
    # app | template | pipeline | sc-product | lambda-pipeline | monitoring | governance
    purpose: str
    size_kb: int
    applies_to_aplicativos: tuple[str, ...] = ()  # FLEET_OPS_APP · SRG · Robot · etc.
    local_path: Optional[str] = None  # relative to ACME Apps Satelites/ si clonado


@dataclass(frozen=True)
class ScProduct:
    """Un producto del Service Catalog (dyn-devops-service-catalog)."""
    name: str             # file stem p.ej. "eks_cluster_product"
    category: str         # infra | pipeline | notification | other
    description: str
    use_for: tuple[str, ...] = ()  # Block 8 · Block 5 · etc.


@dataclass(frozen=True)
class AplicativoMapping:
    """Mapping de un aplicativo del scope eTribe a sus análogos BO-ACME."""
    aplicativo: str         # FLEET_OPS_APP · SRG · etc.
    stack_actual: str
    stack_target: str
    best_analogs: tuple[str, ...]      # repo names
    sc_products_recommended: tuple[str, ...]
    gaps: tuple[str, ...] = ()  # patterns NO existen en BO-ACME · pionero


# ═══════════════════════════════════════════════════════════════════════════
# 95 repos BO-ACME · inventariados 2026-04-24 (subset documented · rest meta)
# ═══════════════════════════════════════════════════════════════════════════

AMX_REPOS: tuple[AmxRepo, ...] = (
    # === Templates canónicos Corporate Solutions (CS-*) · 6 ===
    AmxRepo("CS-App-Template", None, "Template for App Repositories (GitLab Flow)",
            "template", 14,
            applies_to_aplicativos=("FLEET_OPS_APP", "SRG", "Robot", "NoShow", "CFDIs",
                                    "ARC", "BSP", "ASR"),
            local_path="_templates/CS-App-Template"),
    AmxRepo("CS-CICD-Template", None, "Template for App CICD Repositories (GitHub Flow)",
            "template", 14,
            applies_to_aplicativos=("FLEET_OPS_APP", "SRG", "Robot", "NoShow", "CFDIs"),
            local_path="_templates/CS-CICD-Template"),
    AmxRepo("CS-IaC-Template", None, "Template for IaC Repositories (GitLab Flow)",
            "template", 0,
            applies_to_aplicativos=("FLEET_OPS_APP", "SRG", "NoShow"),
            local_path=None),
    AmxRepo("CS-IaC-CICD-Template", "Shell", "IaC Pipeline Template",
            "template", 500,
            applies_to_aplicativos=("FLEET_OPS_APP", "SRG", "NoShow", "Robot"),
            local_path="_templates/CS-IaC-CICD-Template"),
    AmxRepo("CS_CI_Artifacts", "Shell", "Artefactos para pipelines de CS",
            "template", 2000,
            applies_to_aplicativos=("*",)),
    AmxRepo("CS_Scripts", "Shell", "CS Helper Scripts",
            "template", 138063,
            applies_to_aplicativos=("*",)),
    AmxRepo("CS-Mon-Template", "Python",
            "Monitoring Base Repository for CloudWatch Existant Metrics",
            "monitoring", 166,
            applies_to_aplicativos=("FLEET_OPS_APP", "SRG", "NoShow", "Robot", "CFDIs"),
            local_path="_templates/CS-Mon-Template"),
    AmxRepo("CS_Lambda_AuthZ_Template", "Java",
            "Corporate Solutions Lambda Authorizer (AuthZ) Repository Template",
            "template", 2275,
            applies_to_aplicativos=("FLEET_OPS_APP", "SRG", "CFDIs"),
            local_path="_references/CS_Lambda_AuthZ_Template"),

    # === Service Catalog frameworks ===
    AmxRepo("dyn-devops-service-catalog", "Python",
            "AWS Service Catalog CDK framework with 15+ DevOps products",
            "sc-product", 31313,
            applies_to_aplicativos=("*",),
            local_path="_templates/dyn-devops-service-catalog"),
    AmxRepo("sbx-devops-service-catalog", "Python",
            "Service Catalog CDK sandbox/preprod environment",
            "sc-product", 30833,
            applies_to_aplicativos=("*",),
            local_path="_analogos/sbx-devops-service-catalog"),
    AmxRepo("dyn-devops-lib", "Python", "CDK Constructs library · dyn env",
            "sc-product", 1130),
    AmxRepo("sbx-devops-lib", "Python", "CDK Constructs library · sbx env",
            "sc-product", 1130),
    AmxRepo("cx-devops-lib", "Python", "CDK Constructs library · cx env",
            "sc-product", 104),

    # === Apps con código funcional (inspirarse arquitectura) ===
    AmxRepo("RevAcc_Praxis_ASIS_SICOFAV", "C#", "Finance Operations FLEET_OPS_APP",
            "app", 11313,
            applies_to_aplicativos=("FLEET_OPS_APP",)),
    AmxRepo("RevAcc_Praxis_ASIS_SRG", "C#", "Finance Operations SRG",
            "app", 13414,
            applies_to_aplicativos=("SRG",)),
    AmxRepo("RevAcc_Praxis_ASIS_Rob_analisis_VCRS_PNRs_asoc_PLM", "Visual Basic .NET",
            "Finance Operations VCRs PNRs · Robot +11", "app", 11408,
            applies_to_aplicativos=("Robot",)),
    AmxRepo("RevAcc_Praxis_ASIS_Rob_cal_reemb_ven_indi", "Visual Basic .NET",
            "Finance Operations Rob Reembolso Ven · Robot principal", "app", 12083,
            applies_to_aplicativos=("Robot",)),
    AmxRepo("RevAcc_Praxis_ASIS_Rob_cambio_status", "Visual Basic .NET",
            "Finance Operations Cambios Status · Robot +13", "app", 11531,
            applies_to_aplicativos=("Robot",)),
    AmxRepo("RevAcc_Praxis_ASIS_Serv_de_cons_PNRs_VCRs", "Visual Basic .NET",
            "Finance Operations Cons PNRs · Robot +12", "app", 11394,
            applies_to_aplicativos=("Robot",)),
    AmxRepo("FEBOL_MX_DescargaMasivaSAT", "JavaScript",
            "Portal Web Descarga Masiva SAT · poliglota (.NET + Java + Node + Python)",
            "app", 23957,
            applies_to_aplicativos=("CFDIs",),
            local_path="_analogos/FEBOL_MX_DescargaMasivaSAT"),
    AmxRepo("FEI_Extraccion_SFTP_ARCHIVO_BI", "Python",
            "SFTP extraction → BI · integración externa pattern", "app", 2293,
            applies_to_aplicativos=("CFDIs",),
            local_path="_references/FEI_Extraccion_SFTP_ARCHIVO_BI"),
    AmxRepo("TestSecurity-VM", "Python",
            "Repo clonado de Dynamics/Ciberseguridad (readonly)", "app", 2015),

    # === Per-aplicativo pipelines (muestra · no exhaustivo) ===
    AmxRepo("RevAcc_Praxis_ASIS_CI", "Shell", "Finance Operations CI pipeline",
            "pipeline", 5000,
            applies_to_aplicativos=("FLEET_OPS_APP", "SRG", "Robot", "NoShow", "CFDIs",
                                    "ARC", "BSP", "ASR"),
            local_path="_analogos/RevAcc_Praxis_ASIS_CI"),
    AmxRepo("RevAcc_Praxis_ASIS_CD", "Shell", "Finance Operations CD pipeline",
            "pipeline", 6000,
            applies_to_aplicativos=("FLEET_OPS_APP", "SRG", "Robot", "NoShow", "CFDIs"),
            local_path="_analogos/RevAcc_Praxis_ASIS_CD"),
    AmxRepo("Miacmeair_EKS_CICD", "Shell",
            "EKS IaC Pipeline for Miacmeair · pattern para apps EKS",
            "pipeline", 4000,
            applies_to_aplicativos=("FLEET_OPS_APP",),
            local_path="_analogos/Miacmeair_EKS_CICD"),
    AmxRepo("miacmeair_IaC_CICD", "Shell",
            "IaC Pipeline for Miacmeair Application", "pipeline", 3000),

    # === Lambda-per-feature pipelines (SIAC · Nomibox · SAC) ===
    # Muestra representativa · total SIAC=28, SAC=5, Nomibox=4
    AmxRepo("SIAC_IaC_CICD", "Shell", "IaC Pipeline for SIAC",
            "lambda-pipeline", 3000),
    AmxRepo("SIAC_LambdaAuth_CI", "Shell", "CI Pipeline LambdaAuth",
            "lambda-pipeline", 1000,
            applies_to_aplicativos=("FLEET_OPS_APP", "SRG", "CFDIs")),
    AmxRepo("Nomibox_IaC_CICD", "Shell", "Nomibox IaC Pipeline",
            "lambda-pipeline", 3000),

    # === Governance / rules ===
    AmxRepo("amazon-q-rules", "Shell",
            "Project rules for Amazon Q chat · 35 reglas canónicas ACME",
            "governance", 500,
            applies_to_aplicativos=("*",),
            local_path="_templates/amazon-q-rules"),
    AmxRepo("devops-kiro-gov", None,
            "DevOps Service Catalog Kiro Governance Repo",
            "governance", 267,
            local_path="_templates/devops-kiro-gov"),
    AmxRepo("RE_Cost_Optimization_Tools", None,
            "Emergency Response Cost Optimization Repository",
            "governance", 11),
    AmxRepo("CS_Cost_Optimization_Tools", "Shell",
            "Corporate Solutions Cost Optimization Repository",
            "governance", 500),

    # === Monitoring templates ===
    AmxRepo("CTA_IaC_Monitoring", "Python",
            "CTA Monitoring Repository for CloudWatch Existant Metrics",
            "monitoring", 143,
            applies_to_aplicativos=("*",)),
    AmxRepo("PI_IaC_Monitoring", "Python",
            "Monitoring Repository for Portal Intranet",
            "monitoring", 143),
)


# ═══════════════════════════════════════════════════════════════════════════
# Service Catalog products (dyn-devops-service-catalog/products/*)
# ═══════════════════════════════════════════════════════════════════════════

SC_PRODUCTS: tuple[ScProduct, ...] = (
    # Infraestructura
    ScProduct("eks_cluster_product", "infra",
              "EKS cluster con acme-cdk-wrapper · soporta multi-region T0",
              use_for=("Block 8 FLEET_OPS_APP", "Block 8 Com-Indirectas")),
    ScProduct("eks_access_product", "infra",
              "IRSA roles + aws-auth configmap",
              use_for=("Block 8 FLEET_OPS_APP",)),
    ScProduct("eks_addon_product", "infra",
              "CloudWatch agent · metrics server · cluster addons",
              use_for=("Block 3 Observability",)),
    ScProduct("eks_fargate_product", "infra",
              "EKS Fargate · deploy sin EC2 workers",
              use_for=("NoShow (refactor Fargate)",)),
    ScProduct("ec2_eks_access_product", "infra",
              "EC2 worker node access hybrid",
              use_for=("Block 8 futuro",)),
    ScProduct("ecr_product", "infra",
              "ECR repo con scan on push + lifecycle policy",
              use_for=("Block 8 FLEET_OPS_APP", "SRG", "Robot")),
    ScProduct("cloudfront_s3_website_product", "infra",
              "CloudFront + S3 website con OAC (no OAI deprecated)",
              use_for=("SRG frontend", "CFDIs portal")),
    ScProduct("database_migration_product", "infra",
              "DMS para migración MySQL 5.7 → Aurora MySQL 8",
              use_for=("FLEET_OPS_APP cutover", "Com-Indirectas")),
    ScProduct("cross_resources_product", "infra",
              "Cross-account role assumption",
              use_for=("Block 8 FLEET_OPS_APP multi-region",)),

    # Pipelines
    ScProduct("pipeline_api_gateway_rest_sam_product", "pipeline",
              "API Gateway REST + SAM CI/CD",
              use_for=("Block 5 API FLEET_OPS_APP", "SRG API refactor")),
    ScProduct("pipeline_api_gateway_http_sam_product", "pipeline",
              "API Gateway HTTP + SAM · más barato · menos features",
              use_for=("APIs internas ligeras",)),
    ScProduct("pipeline_api_gateway_web_socket_sam_product", "pipeline",
              "API Gateway WebSocket · real-time notifications",
              use_for=("SRG SignalR migration",)),
    ScProduct("pipeline_base_product", "pipeline", "Pipeline base genérico"),
    ScProduct("pipeline_base_product_on_premise_microservice", "pipeline",
              "Microservicio on-prem genérico"),
    ScProduct("pipeline_base_product_on_premise_microservice_jdk11", "pipeline",
              "Microservicio on-prem JDK 11"),
    ScProduct("pipeline_base_product_on_premise_microservice_jdk17", "pipeline",
              "Microservicio on-prem JDK 17"),
    ScProduct("pipeline_base_product_on_premise_monolith", "pipeline",
              "Monolito on-prem · útil cutover gradual",
              use_for=("FLEET_OPS_APP cutover fase intermedia",)),
    ScProduct("pipeline_csby_middleware_product", "pipeline",
              "Middleware Corp Service Bus ACME",
              use_for=("Integración Praxis",)),

    # Notification / Other
    ScProduct("lambda_notification_product", "notification",
              "Lambda + SNS pattern para notifications",
              use_for=("Block 3 Observability alerts",)),
    ScProduct("notification_rule_product", "notification",
              "CloudWatch rule + target",
              use_for=("Block 3 alerting",)),
)


# ═══════════════════════════════════════════════════════════════════════════
# Mapping 10 aplicativos → análogos recomendados
# ═══════════════════════════════════════════════════════════════════════════

APLICATIVO_ANALOGS: tuple[AplicativoMapping, ...] = (
    AplicativoMapping(
        aplicativo="FLEET_OPS_APP",
        stack_actual=".NET Framework 4.7 + MySQL 5.7",
        stack_target=".NET 8 + EKS multi-región + Aurora Global",
        best_analogs=("dyn-devops-service-catalog", "CS_Lambda_AuthZ_Template",
                      "RevAcc_Praxis_ASIS_CI", "RevAcc_Praxis_ASIS_CD",
                      "CS-Mon-Template", "Miacmeair_EKS_CICD"),
        sc_products_recommended=("eks_cluster_product", "eks_access_product",
                                 "eks_addon_product", "ecr_product",
                                 "pipeline_api_gateway_rest_sam_product",
                                 "database_migration_product",
                                 "lambda_notification_product",
                                 "cross_resources_product"),
    ),
    AplicativoMapping(
        aplicativo="SRG",
        stack_actual=".NET 7 + Angular 15 (ambos EOL)",
        stack_target=".NET 8 + Angular 17 LTS",
        best_analogs=("RevAcc_Praxis_ASIS_SICOFAV", "CS-App-Template",
                      "RevAcc_Praxis_ASIS_CI"),
        sc_products_recommended=("ecr_product", "cloudfront_s3_website_product",
                                 "pipeline_api_gateway_rest_sam_product"),
        gaps=("No hay ejemplo Angular 17 moderno · SRG será pionero",),
    ),
    AplicativoMapping(
        aplicativo="Robot",
        stack_actual="VB.NET 4.6/4.7 + DPAPI Windows",
        stack_target="C# .NET 8 + Secrets Manager",
        best_analogs=("RevAcc_Praxis_ASIS_SICOFAV",),
        sc_products_recommended=("eks_fargate_product", "ecr_product"),
        gaps=("No hay ejemplo VB.NET → C# migration · Robot será pionero",),
    ),
    AplicativoMapping(
        aplicativo="NoShow",
        stack_actual=".NET 4.7 (legacy · parcialmente refactored)",
        stack_target=".NET 8 + Fargate",
        best_analogs=("dyn-devops-service-catalog", "CS-Mon-Template"),
        sc_products_recommended=("eks_fargate_product", "ecr_product",
                                 "lambda_notification_product"),
    ),
    AplicativoMapping(
        aplicativo="CFDIs",
        stack_actual="skeleton (DxC vs BO-ACME inconsistencia)",
        stack_target="descarga + procesamiento CFDIs SAT Mexico",
        best_analogs=("FEBOL_MX_DescargaMasivaSAT", "FEI_Extraccion_SFTP_ARCHIVO_BI",
                      "CS_Lambda_AuthZ_Template"),
        sc_products_recommended=("pipeline_api_gateway_rest_sam_product",
                                 "cloudfront_s3_website_product",
                                 "lambda_notification_product"),
    ),
    AplicativoMapping(
        aplicativo="ARC",
        stack_actual="skeleton Miatech pending push",
        stack_target="pending decision",
        best_analogs=("RevAcc_Praxis_ASIS_SICOFAV", "CS-App-Template"),
        sc_products_recommended=(),
    ),
    AplicativoMapping(
        aplicativo="BSP",
        stack_actual="VB.NET (dentro Robot composite · submódulo BSPRefunds/)",
        stack_target="TBD post-separación",
        best_analogs=("RevAcc_Praxis_ASIS_Rob_cal_reemb_ven_indi",
                      "RevAcc_Praxis_ASIS_SICOFAV"),
        sc_products_recommended=("ecr_product",),
    ),
    AplicativoMapping(
        aplicativo="ASR",
        stack_actual="skeleton Miatech",
        stack_target="pending stack decision",
        best_analogs=("CS-App-Template",),
        sc_products_recommended=(),
    ),
    AplicativoMapping(
        aplicativo="Com-Directas",
        stack_actual="AS400 Peru ATOS-LIMA 2009 (STANDBY #8)",
        stack_target="pending governance desbloqueo",
        best_analogs=(),
        sc_products_recommended=(),
        gaps=("No hay análogos AS400/RPG en BO-ACME accesibles",),
    ),
    AplicativoMapping(
        aplicativo="Com-Indirectas",
        stack_actual="AWS Aurora Miatech (STANDBY #9)",
        stack_target="pending governance",
        best_analogs=("dyn-devops-service-catalog",),
        sc_products_recommended=("database_migration_product",
                                 "eks_cluster_product"),
    ),
)


# ═══════════════════════════════════════════════════════════════════════════
# Query functions
# ═══════════════════════════════════════════════════════════════════════════

def list_repos(purpose: Optional[str] = None,
               language: Optional[str] = None,
               aplicativo: Optional[str] = None) -> list[AmxRepo]:
    """Lista repos con filtros opcionales."""
    results = list(AMX_REPOS)
    if purpose:
        results = [r for r in results if r.purpose == purpose]
    if language:
        results = [r for r in results
                   if (r.language or "").lower() == language.lower()]
    if aplicativo:
        aplicativo_lower = aplicativo.lower()
        results = [r for r in results
                   if any(a.lower() == aplicativo_lower or a == "*"
                          for a in r.applies_to_aplicativos)]
    return results


def search_repos(query: str) -> list[AmxRepo]:
    """Busca en name · description · purpose · case-insensitive."""
    q = query.lower()
    return [r for r in AMX_REPOS
            if q in r.name.lower()
            or q in r.description.lower()
            or q in r.purpose.lower()]


def get_repo(name: str) -> Optional[AmxRepo]:
    """Retorna un repo por nombre exacto."""
    for r in AMX_REPOS:
        if r.name == name:
            return r
    return None


def list_sc_products(category: Optional[str] = None) -> list[ScProduct]:
    """Lista productos Service Catalog por categoría opcional."""
    if not category:
        return list(SC_PRODUCTS)
    return [p for p in SC_PRODUCTS if p.category == category]


def get_aplicativo_mapping(aplicativo: str) -> Optional[AplicativoMapping]:
    """Retorna el mapping de análogos para un aplicativo específico."""
    app_lower = aplicativo.lower()
    for m in APLICATIVO_ANALOGS:
        if m.aplicativo.lower() == app_lower:
            return m
    return None


# ═══════════════════════════════════════════════════════════════════════════
# Analog fingerprinting · detecta stack de un repo y sugiere análogos
# ═══════════════════════════════════════════════════════════════════════════

def fingerprint_repo(root: Path) -> dict:
    """Escanea `root` y detecta stack + dominio · heurística de extensiones
    + nombres de archivos emblemáticos.
    """
    root = Path(root).resolve()
    result = {
        "root": str(root),
        "languages": set(),
        "frameworks": set(),
        "signals": [],
    }

    if not root.exists():
        result["error"] = f"{root} no existe"
        result["languages"] = []
        result["frameworks"] = []
        return result

    # Lang detection por extensiones
    ext_counts: dict[str, int] = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        # Skip dirs grandes que distorsionan
        rel = p.relative_to(root)
        parts = rel.parts
        if any(x in parts for x in ("node_modules", "bin", "obj", ".git",
                                     "__pycache__", "packages", "dist",
                                     "build", ".next", "venv", ".venv")):
            continue
        ext = p.suffix.lower()
        ext_counts[ext] = ext_counts.get(ext, 0) + 1

    # Map extensions → languages/frameworks
    mapping = {
        ".cs": ("C#", None),
        ".csproj": ("C#", ".NET"),
        ".sln": ("C#", ".NET"),
        ".vb": ("VB.NET", ".NET Framework"),
        ".vbproj": ("VB.NET", ".NET Framework"),
        ".fs": ("F#", ".NET"),
        ".py": ("Python", None),
        ".java": ("Java", None),
        ".kt": ("Kotlin", None),
        ".ts": ("TypeScript", None),
        ".tsx": ("TypeScript", "React"),
        ".js": ("JavaScript", None),
        ".jsx": ("JavaScript", "React"),
        ".go": ("Go", None),
        ".rs": ("Rust", None),
    }
    # Project marker extensions · cuentan siempre (1 solo archivo suficiente)
    project_markers = {".sln", ".csproj", ".vbproj", ".fsproj"}

    for ext, n in ext_counts.items():
        if ext not in mapping:
            continue
        # archivos source · requiere ≥ 2 para evitar FPs
        # project markers · siempre cuentan (un .sln indica .NET solution)
        if ext not in project_markers and n < 2:
            continue
        lang, fw = mapping[ext]
        result["languages"].add(lang)
        if fw:
            result["frameworks"].add(fw)

    # Signals · archivos emblemáticos
    signal_files = {
        "package.json": "Node.js project",
        "requirements.txt": "Python project",
        "pyproject.toml": "Python project",
        "cdk.json": "AWS CDK project",
        "template.yaml": "AWS SAM project",
        "serverless.yml": "Serverless framework",
        "angular.json": "Angular",
        "vite.config.ts": "Vite",
        "Dockerfile": "Containerized",
        "docker-compose.yml": "Docker Compose",
        "buildspec.yaml": "AWS CodeBuild",
        "buildspec.yml": "AWS CodeBuild",
        "terraform.tf": "Terraform",
        "main.tf": "Terraform",
        "Chart.yaml": "Helm chart",
        "web.config": "ASP.NET Framework",
        "appsettings.json": "ASP.NET Core",
        "Web.config": "ASP.NET Framework",
    }
    for fname, signal in signal_files.items():
        if list(root.rglob(fname))[:1]:
            result["signals"].append(signal)

    # Frameworks desde signals
    if "Angular" in result["signals"]:
        result["frameworks"].add("Angular")
    if "ASP.NET Core" in str(result["signals"]):
        result["frameworks"].add("ASP.NET Core")

    # Cast sets a lists para serializar
    result["languages"] = sorted(result["languages"])
    result["frameworks"] = sorted(result["frameworks"])
    result["signals"] = sorted(set(result["signals"]))
    return result


def suggest_analogs(fingerprint: dict) -> list[AmxRepo]:
    """Dado un fingerprint · retorna repos ACME candidatos."""
    langs = [l.lower() for l in fingerprint.get("languages", [])]
    frameworks = [f.lower() for f in fingerprint.get("frameworks", [])]
    signals = [s.lower() for s in fingerprint.get("signals", [])]

    candidates: list[tuple[int, AmxRepo]] = []
    for r in AMX_REPOS:
        score = 0
        if r.language and r.language.lower() in langs:
            score += 3
        desc_low = (r.description or "").lower()
        name_low = r.name.lower()
        for fw in frameworks:
            if fw in desc_low or fw in name_low:
                score += 2
        for sg in signals:
            # Extrae keywords técnicas · "aws cdk project" → cada palabra
            # significativa (>=3 chars) se busca en desc/name
            for key in sg.split():
                k = key.lower()
                if len(k) < 3 or k in ("the", "and", "for", "with"):
                    continue
                if k in desc_low or k in name_low:
                    score += 1
        if score > 0:
            candidates.append((score, r))

    candidates.sort(key=lambda t: (-t[0], t[1].name))
    return [r for _, r in candidates[:15]]
