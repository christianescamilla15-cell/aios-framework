"""Catálogo de la organización · repos internos, plantillas y productos del catálogo de servicios.

Registro estructurado para que AIOS pueda:

1. Sugerir repos análogos cuando una aplicación arranca su modernización (`aios org-analog`)
2. Listar los productos del catálogo de servicios cloud preaprobados
3. Señalar las plantillas que deben reutilizarse en vez de reinventarse

Los datos de este módulo describen a **Acme Corp, una organización ficticia**: los nombres de repos,
productos y aplicaciones son inventados. Para una organización real, reemplaza `ORG_REPOS`,
`SC_PRODUCTS` y `APP_ANALOGS` por su inventario (p. ej. generado con `gh repo list <org> --json`).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# Último refresh de datos · YYYY-MM-DD
CATALOG_LAST_REFRESHED = "2026-11-24"

# TTL recomendado antes de refrescar el inventario (días)
CATALOG_TTL_DAYS = 90


@dataclass(frozen=True)
class OrgRepo:
    """Un repo de la organización con metadata relevante."""
    name: str
    language: Optional[str]   # C#, VB.NET, Python, Shell, Java, TypeScript, None
    description: str
    # app | template | pipeline | sc-product | monitoring | governance
    purpose: str
    size_kb: int
    applies_to_apps: tuple[str, ...] = ()  # "*" = todas
    local_path: Optional[str] = None       # relativo a la carpeta de clones locales


@dataclass(frozen=True)
class ScProduct:
    """Un producto del catálogo de servicios cloud preaprobado."""
    name: str
    category: str         # infra | pipeline | notification | other
    description: str
    use_for: tuple[str, ...] = ()


@dataclass(frozen=True)
class AppMapping:
    """Mapeo de una aplicación a sus análogos dentro de la organización."""
    app: str
    stack_actual: str
    stack_target: str
    best_analogs: tuple[str, ...]          # nombres de repo
    sc_products_recommended: tuple[str, ...]
    gaps: tuple[str, ...] = ()             # patrones sin precedente en la organización


# ═══════════════════════════════════════════════════════════════════════════
# Repos de la organización (ficticios)
# ═══════════════════════════════════════════════════════════════════════════

ORG_REPOS: tuple[OrgRepo, ...] = (
    # === Plantillas canónicas · 6 ===
    OrgRepo("acme-app-template", None, "Plantilla para repos de aplicación (GitLab Flow)",
            "template", 14, applies_to_apps=("*",), local_path="_templates/acme-app-template"),
    OrgRepo("acme-cicd-template", None, "Plantilla para repos de pipeline (GitHub Flow)",
            "template", 14, applies_to_apps=("*",)),
    OrgRepo("acme-iac-template", "Python", "Plantilla de infraestructura como código con AWS CDK",
            "template", 40, applies_to_apps=("*",)),
    OrgRepo("acme-monitoring-template", "Python", "Plantilla de tableros y alarmas de observabilidad",
            "template", 22, applies_to_apps=("*",)),
    OrgRepo("acme-lambda-authz-template", "Python", "Plantilla de autorizador para API Gateway",
            "template", 18, applies_to_apps=("Billing", "Orders", "Partners")),
    OrgRepo("acme-docs-template", None, "Plantilla de documentación (C4, ADR, runbook)",
            "template", 9, applies_to_apps=("*",)),

    # === Catálogo de servicios y pipelines ===
    OrgRepo("acme-service-catalog", "Python",
            "Framework del catálogo de servicios cloud preaprobados (productos CDK)",
            "sc-product", 310, applies_to_apps=("*",)),
    OrgRepo("acme-eks-cicd", "Shell", "Pipeline de despliegue a EKS con plantillas Helm",
            "pipeline", 75, applies_to_apps=("Orders", "Shipping")),
    OrgRepo("acme-lambda-pipeline", "Python", "Pipeline de empaquetado y despliegue de funciones Lambda",
            "pipeline", 31, applies_to_apps=("Reports",)),

    # === Aplicaciones heredadas (AS-IS) ===
    OrgRepo("acme-legacy-billing", "C#", "Facturación heredada en ASP.NET Framework con SQL Server",
            "app", 5200, applies_to_apps=("Billing",)),
    OrgRepo("acme-legacy-orders", "VB.NET", "Captura de pedidos heredada en WinForms",
            "app", 3900, applies_to_apps=("Orders",)),
    OrgRepo("acme-partners-portal", "TypeScript", "Portal de socios en Angular con API .NET",
            "app", 2100, applies_to_apps=("Partners",)),
    OrgRepo("acme-reports-jobs", "Python", "Reportes nocturnos como funciones Lambda programadas",
            "app", 640, applies_to_apps=("Reports",)),
    OrgRepo("acme-payments-gateway", "Java", "Pasarela de cobro con tarjeta en Spring Boot",
            "app", 2800, applies_to_apps=("Payments",)),

    # === Gobierno y observabilidad ===
    OrgRepo("acme-compliance-scripts", "Shell", "Scripts de verificación de cumplimiento de repos",
            "governance", 12, applies_to_apps=("*",)),
    OrgRepo("acme-observability", "Python", "Exportadores de métricas y tableros compartidos",
            "monitoring", 88, applies_to_apps=("*",)),
)


# ═══════════════════════════════════════════════════════════════════════════
# Productos del catálogo de servicios (ficticios)
# ═══════════════════════════════════════════════════════════════════════════

SC_PRODUCTS: tuple[ScProduct, ...] = (
    ScProduct("eks-cluster", "infra", "Clúster EKS con nodos administrados y complementos base",
              ("contenedores",)),
    ScProduct("container-registry", "infra", "Registro de imágenes con escaneo al subir",
              ("contenedores",)),
    ScProduct("aurora-cluster", "infra", "Clúster Aurora con cifrado y respaldo continuo",
              ("base de datos",)),
    ScProduct("object-bucket", "infra", "Bucket con cifrado, bloqueo de acceso público y ciclo de vida",
              ("almacenamiento",)),
    ScProduct("lambda-function", "infra", "Función Lambda con rol mínimo y retención de bitácoras",
              ("serverless",)),
    ScProduct("rest-api", "infra", "API Gateway REST privada con autorizador", ("APIs",)),
    ScProduct("message-queue", "infra", "Cola SQS cifrada con cola de mensajes fallidos", ("mensajería",)),
    ScProduct("key-value-table", "infra", "Tabla DynamoDB cifrada con PITR", ("base de datos",)),
    ScProduct("cdn-distribution", "infra", "Distribución CloudFront con OAC y WAF", ("front estático",)),
    ScProduct("web-firewall", "infra", "WebACL con reglas administradas base", ("APIs", "front")),
    ScProduct("kms-key", "infra", "Llave KMS administrada por el cliente con rotación", ("cifrado",)),
    ScProduct("secret", "infra", "Secreto con rotación programada", ("credenciales",)),
    ScProduct("vpc-endpoint", "infra", "Endpoint de VPC de interfaz", ("red privada",)),
    ScProduct("log-group", "infra", "Grupo de bitácoras con retención y cifrado", ("observabilidad",)),
    ScProduct("rest-api-sam-pipeline", "pipeline", "Pipeline para API REST con SAM", ("APIs",)),
    ScProduct("lambda-pipeline", "pipeline", "Pipeline para funciones Lambda", ("serverless",)),
    ScProduct("container-pipeline", "pipeline", "Pipeline de imagen → registro → EKS", ("contenedores",)),
    ScProduct("static-site-pipeline", "pipeline", "Pipeline de front estático a bucket + CDN", ("front",)),
    ScProduct("email-relay", "notification", "Envío de correo por el relevo interno", ("notificaciones",)),
)


# ═══════════════════════════════════════════════════════════════════════════
# Mapeo aplicación → análogos (ficticio)
# ═══════════════════════════════════════════════════════════════════════════

APP_ANALOGS: tuple[AppMapping, ...] = (
    AppMapping("Billing", "ASP.NET Framework 4.8 + SQL Server", ".NET 8 + Aurora PostgreSQL en EKS",
               ("acme-legacy-billing", "acme-service-catalog", "acme-app-template"),
               ("eks-cluster", "aurora-cluster", "kms-key", "container-pipeline")),
    AppMapping("Orders", "VB.NET WinForms + SQL Server", ".NET 8 API + front React en EKS",
               ("acme-legacy-orders", "acme-eks-cicd", "acme-app-template"),
               ("eks-cluster", "container-registry", "aurora-cluster")),
    AppMapping("Shipping", "Java 8 monolito", "Java 21 + Spring Boot en EKS",
               ("acme-eks-cicd", "acme-app-template"),
               ("eks-cluster", "message-queue")),
    AppMapping("FaxGateway", "Servicio Windows", "Fuera de alcance (se retira)", (), (),
               ("Sin análogo: se retira sin migrar",)),
    AppMapping("Partners", "Angular 15 + .NET 7", "Angular 18 + .NET 8 en EKS",
               ("acme-partners-portal", "acme-lambda-authz-template"),
               ("eks-cluster", "cdn-distribution", "web-firewall")),
    AppMapping("Support", "PHP 7", "Python 3.12 serverless",
               ("acme-lambda-pipeline", "acme-app-template"),
               ("lambda-function", "rest-api", "key-value-table")),
    AppMapping("Payments", "Java 11 + Spring Boot", "Java 21 en EKS con alcance PCI",
               ("acme-payments-gateway", "acme-eks-cicd"),
               ("eks-cluster", "kms-key", "secret"),
               ("Segmentación PCI sin precedente en la organización",)),
    AppMapping("Reports", "Python 3.8 en cron", "Python 3.12 Lambda programada",
               ("acme-reports-jobs", "acme-lambda-pipeline"),
               ("lambda-function", "lambda-pipeline", "log-group")),
)


# ═══════════════════════════════════════════════════════════════════════════
# Query functions
# ═══════════════════════════════════════════════════════════════════════════

def list_repos(purpose: Optional[str] = None,
               language: Optional[str] = None,
               app: Optional[str] = None) -> list[OrgRepo]:
    """Lista repos con filtros opcionales."""
    results = list(ORG_REPOS)
    if purpose:
        results = [r for r in results if r.purpose == purpose]
    if language:
        results = [r for r in results
                   if (r.language or "").lower() == language.lower()]
    if app:
        app_lower = app.lower()
        results = [r for r in results
                   if any(a.lower() == app_lower or a == "*"
                          for a in r.applies_to_apps)]
    return results


def search_repos(query: str) -> list[OrgRepo]:
    """Busca en name · description · purpose · case-insensitive."""
    q = query.lower()
    return [r for r in ORG_REPOS
            if q in r.name.lower()
            or q in r.description.lower()
            or q in r.purpose.lower()]


def get_repo(name: str) -> Optional[OrgRepo]:
    """Retorna un repo por nombre exacto."""
    for r in ORG_REPOS:
        if r.name == name:
            return r
    return None


def list_sc_products(category: Optional[str] = None) -> list[ScProduct]:
    """Lista productos Service Catalog por categoría opcional."""
    if not category:
        return list(SC_PRODUCTS)
    return [p for p in SC_PRODUCTS if p.category == category]


def get_app_mapping(app: str) -> Optional[AppMapping]:
    """Retorna el mapeo de análogos de una aplicación (sin distinguir mayúsculas)."""
    app_lower = app.lower()
    for m in APP_ANALOGS:
        if m.app.lower() == app_lower:
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


def suggest_analogs(fingerprint: dict) -> list[OrgRepo]:
    """Dado un fingerprint · retorna repos del catálogo candidatos a análogo."""
    langs = [l.lower() for l in fingerprint.get("languages", [])]
    frameworks = [f.lower() for f in fingerprint.get("frameworks", [])]
    signals = [s.lower() for s in fingerprint.get("signals", [])]

    candidates: list[tuple[int, OrgRepo]] = []
    for r in ORG_REPOS:
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
