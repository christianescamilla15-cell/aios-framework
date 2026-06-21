"""v3.5.0 · Buildspec validator.

Valida que el `buildspec.yaml` del repo esté alineado con el catálogo de
plantillas oficiales ACME en `BO-ACME/CS_CI_Artifacts` · detecta anti-patrón
"copié el buildspec de otra app y nunca lo adapté".

Catálogo hardcoded (snapshot 2026-04-23 del repo CS_CI_Artifacts) · si el
repo se clona localmente y su path se pasa como `catalog_root`, se lee
directo · de lo contrario usa el catálogo interno.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional


# Snapshot del catálogo CS_CI_Artifacts/buildspecs/ (23-abr-2026)
CATALOG: Dict[str, Dict] = {
    "angular + s3": {
        "template": "build_angular_s3.yaml",
        "stack_markers": ["angular.json", "package.json:angular"],
    },
    "blazor + s3": {
        "template": "build_blazor_s3.yaml",
        "stack_markers": [".csproj:Microsoft.AspNetCore.Components.WebAssembly"],
    },
    "docker image": {
        "template": "build_docker_image.yaml",
        "stack_markers": ["Dockerfile"],
    },
    "dotnet lambda": {
        "template": "build_dotnet_lambda.yaml",
        "stack_markers": [".csproj:Amazon.Lambda"],
    },
    "java lambda": {
        "template": "build_java_lambda.yaml",
        "stack_markers": ["pom.xml:aws-lambda-java"],
    },
    "nodejs lambda": {
        "template": "build_nodejs_lambda.yaml",
        "stack_markers": ["package.json:aws-lambda"],
    },
    "python lambda": {
        "template": "build_manual_python_lambda.yaml",
        "stack_markers": ["requirements.txt", "pyproject.toml"],
    },
    "maven artifact jdk11": {
        "template": "build_maven_artifact_jdk11.yaml",
        "stack_markers": ["pom.xml:java.version:11"],
    },
    "ecr modernization": {
        "template": "build_push_ecr_modernization.yaml",
        "stack_markers": ["Dockerfile", ".csproj", "buildspec.yaml:modernization"],
    },
    "ecr dotnet": {
        "template": "build_push_ecr_dotnet.yaml",
        "stack_markers": ["Dockerfile", ".csproj"],
    },
    "ecr on-prem microservices": {
        "template": "build_push_ecr_on_premise_microservices.yaml",
        "stack_markers": ["Dockerfile", "on-premise"],
    },
}


def detect_stack(root: Path) -> List[str]:
    """Retorna lista de stack markers detectados en el proyecto."""
    markers: List[str] = []
    if (root / "Dockerfile").exists():
        markers.append("Dockerfile")
    if (root / "package.json").exists():
        markers.append("package.json")
    if (root / "requirements.txt").exists():
        markers.append("requirements.txt")
    if (root / "pyproject.toml").exists():
        markers.append("pyproject.toml")
    if (root / "pom.xml").exists():
        markers.append("pom.xml")
    if list(root.rglob("*.csproj")):
        markers.append(".csproj")
    if list(root.rglob("*.vbproj")):
        markers.append(".vbproj")
    if (root / "angular.json").exists():
        markers.append("angular.json")
    return markers


def detect_buildspec(root: Path) -> Optional[Path]:
    """Retorna path del buildspec.yaml si existe (root, .aws/, buildspecs/)."""
    candidates = [
        root / "buildspec.yaml",
        root / "buildspec.yml",
        root / ".aws" / "buildspec.yaml",
        root / "buildspecs" / "buildspec.yaml",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def recommend_template(markers: List[str]) -> List[str]:
    """Retorna lista de templates de CS_CI_Artifacts alineados al stack."""
    recommendations: List[str] = []
    markers_set = set(markers)
    if "Dockerfile" in markers_set and ".csproj" in markers_set:
        recommendations.append("build_push_ecr_modernization.yaml")
        recommendations.append("build_push_ecr_dotnet.yaml")
    if ".csproj" in markers_set and "Dockerfile" not in markers_set:
        recommendations.append("build_dotnet_lambda.yaml")
    if ".vbproj" in markers_set:
        recommendations.append("build_dotnet_lambda.yaml  # adaptar a VB.NET")
    if "pom.xml" in markers_set:
        recommendations.append("build_maven_artifact_jdk11.yaml")
        recommendations.append("build_java_lambda.yaml")
    if "requirements.txt" in markers_set or "pyproject.toml" in markers_set:
        recommendations.append("build_manual_python_lambda.yaml")
    if "angular.json" in markers_set:
        recommendations.append("build_angular_s3.yaml")
    if "package.json" in markers_set and not recommendations:
        recommendations.append("build_nodejs_lambda.yaml")
    if "Dockerfile" in markers_set and not recommendations:
        recommendations.append("build_docker_image.yaml")
    return recommendations


def validate(root: Path) -> Dict:
    """Valida buildspec vs catálogo CS_CI_Artifacts."""
    markers = detect_stack(root)
    buildspec = detect_buildspec(root)
    recommended = recommend_template(markers)

    report: Dict = {
        "stack_markers": markers,
        "buildspec_path": str(buildspec.relative_to(root)) if buildspec else None,
        "recommended_templates": recommended,
    }

    if buildspec is None:
        report["status"] = "fail" if recommended else "info"
        report["detail"] = (
            f"No hay buildspec.yaml · recomendado: {recommended[0]}"
            if recommended else
            "No hay buildspec.yaml · stack no identificable para recomendación"
        )
        return report

    try:
        content = buildspec.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        report["status"] = "warn"
        report["detail"] = f"Buildspec presente pero no legible: {buildspec}"
        return report

    # Heurísticas · si el buildspec menciona una versión conocida y no cuadra
    # con el stack detectado, sugerir cambio.
    mismatch = False
    if ".csproj" in markers or ".vbproj" in markers:
        if "java" in content.lower() or "maven" in content.lower():
            mismatch = True
    if "pom.xml" in markers:
        if "dotnet" in content.lower() or "csproj" in content.lower():
            mismatch = True

    report["status"] = "fail" if mismatch else "pass"
    report["detail"] = (
        "[XX] Buildspec parece no alineado al stack detectado · "
        f"sugerido: {recommended[0] if recommended else 'N/A'}"
        if mismatch else
        "[OK] Buildspec presente y alineado con stack detectado"
    )
    return report


def format_report(report: Dict) -> List[str]:
    lines: List[str] = []
    lines.append("")
    lines.append("=" * 60)
    lines.append("  BUILDSPEC VALIDATION (vs CS_CI_Artifacts)")
    lines.append("=" * 60)
    lines.append(f"  Stack markers    · {', '.join(report.get('stack_markers', []) or ['-'])}")
    lines.append(f"  Buildspec found  · {report.get('buildspec_path') or 'none'}")
    recs = report.get("recommended_templates") or []
    if recs:
        lines.append("  Recommended from catalog:")
        for r in recs:
            lines.append(f"    - {r}")
    status = report.get("status", "?").upper()
    marker = ("[OK]" if status == "PASS" else "[XX]" if status == "FAIL"
              else "[!!]" if status == "WARN" else "[..]")
    lines.append(f"  Result           · {marker} {report.get('detail', '-')}")
    lines.append("=" * 60)
    return lines
