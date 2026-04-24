"""v3.6.5 · G-22 · SBOM generation (CycloneDX format).

Genera Software Bill of Materials en formato CycloneDX JSON · standard
OWASP · consumible por dependency-track · Snyk · Prisma Cloud · etc.

Soporta:
- Python · vía `cyclonedx-py environment` o `cyclonedx-py requirements`
- Node · vía `cyclonedx-npm` (si instalado)

Uso:
    aios sbom --lang python --root . --output sbom.cdx.json
    aios sbom --lang node --root frontend/
    aios sbom --lang python --format json
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from aios.core.external_scanner_base import run_cli_capture


@dataclass(frozen=True)
class SbomComponent:
    """Un componente en el SBOM (paquete · biblioteca)."""
    name: str
    version: str
    purl: str = ""  # package URL (pkg:pypi/lib@1.0)
    license: str = ""


@dataclass(frozen=True)
class SbomReport:
    root: str
    lang: str  # python | node
    components: list[SbomComponent]
    bom_format: str = "CycloneDX"
    spec_version: str = ""
    scanner_available: bool = True
    output_path: Optional[str] = None
    error: Optional[str] = None
    raw_bom: dict = field(default_factory=dict)


def run_sbom_python(root: Path, timeout_seconds: int = 300) -> dict:
    """cyclonedx-py environment → CycloneDX JSON."""
    # Intento 1 · environment (paquetes instalados en el venv actual)
    cmd = ["cyclonedx-py", "environment", "--output-format", "JSON"]
    cli = run_cli_capture(cmd, cwd=root, timeout_seconds=timeout_seconds)
    if cli.available and cli.stdout and not cli.error:
        try:
            return json.loads(cli.stdout)
        except json.JSONDecodeError:
            pass

    # Intento 2 · requirements.txt si existe
    req = root / "requirements.txt"
    if cli.available and req.exists():
        cmd2 = ["cyclonedx-py", "requirements", str(req),
                "--output-format", "JSON"]
        cli2 = run_cli_capture(cmd2, cwd=root, timeout_seconds=timeout_seconds)
        if cli2.available and cli2.stdout:
            try:
                return json.loads(cli2.stdout)
            except json.JSONDecodeError as e:
                return {"scanner_available": True,
                        "error": f"cyclonedx-py output no es JSON: {e}"}

    if not cli.available:
        return {"scanner_available": False, "error": cli.error}
    return {"scanner_available": True,
            "error": cli.error or "cyclonedx-py no produjo output"}


def run_sbom_node(root: Path, timeout_seconds: int = 300) -> dict:
    """cyclonedx-npm → CycloneDX JSON."""
    cmd = ["cyclonedx-npm", "--output-format", "json"]
    cli = run_cli_capture(cmd, cwd=root, timeout_seconds=timeout_seconds)
    if not cli.available:
        return {"scanner_available": False, "error": cli.error}
    if cli.error and not cli.stdout:
        return {"scanner_available": True, "error": cli.error}
    try:
        return json.loads(cli.stdout) if cli.stdout else {}
    except json.JSONDecodeError as e:
        return {"scanner_available": True,
                "error": f"cyclonedx-npm output no es JSON: {e}"}


def parse_cyclonedx_bom(data: dict, root: str, lang: str) -> SbomReport:
    """Convierte CycloneDX JSON a SbomReport.

    Formato CycloneDX 1.4/1.5:
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.5",
          "components": [
            {
              "type": "library",
              "name": "requests",
              "version": "2.31.0",
              "purl": "pkg:pypi/requests@2.31.0",
              "licenses": [{"license": {"id": "Apache-2.0"}}]
            }
          ]
        }
    """
    if not data.get("scanner_available", True):
        return SbomReport(
            root=root, lang=lang, components=[],
            scanner_available=False, error=data.get("error"),
        )
    if "error" in data:
        return SbomReport(
            root=root, lang=lang, components=[],
            scanner_available=True, error=data["error"],
        )

    components: list[SbomComponent] = []
    for c in data.get("components", []) or []:
        if not isinstance(c, dict):
            continue
        # Extraer primera license
        lic = ""
        licenses = c.get("licenses", []) or []
        if licenses and isinstance(licenses, list):
            first = licenses[0]
            if isinstance(first, dict):
                lic_obj = first.get("license", {})
                if isinstance(lic_obj, dict):
                    lic = str(lic_obj.get("id") or lic_obj.get("name") or "")
        components.append(SbomComponent(
            name=str(c.get("name", "")),
            version=str(c.get("version", "")),
            purl=str(c.get("purl", "")),
            license=lic,
        ))

    return SbomReport(
        root=root, lang=lang, components=components,
        bom_format=str(data.get("bomFormat", "CycloneDX")),
        spec_version=str(data.get("specVersion", "")),
        scanner_available=True, raw_bom=data,
    )


def write_sbom(report: SbomReport, output_path: Path) -> SbomReport:
    """Escribe el BOM raw a disco · retorna report con output_path."""
    if not report.raw_bom:
        return report
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report.raw_bom, indent=2),
                           encoding="utf-8")
    return SbomReport(
        root=report.root, lang=report.lang, components=report.components,
        bom_format=report.bom_format, spec_version=report.spec_version,
        scanner_available=report.scanner_available,
        output_path=str(output_path),
        error=report.error, raw_bom=report.raw_bom,
    )


def format_human(report: SbomReport) -> str:
    out: list[str] = ["", "  SBOM · G-22 · CycloneDX generation",
                      "  " + "-" * 68,
                      f"  Root          : {report.root}",
                      f"  Lang          : {report.lang}"]
    if not report.scanner_available:
        out.append(f"  CLI avail     : NO · {report.error}")
        out.append("  SKIPPED (no blocking)")
        out.append("")
        return "\n".join(out)
    if report.error:
        out.append(f"  ERROR · {report.error}")
        out.append("")
        return "\n".join(out)

    out.append(f"  Format        : {report.bom_format} {report.spec_version}")
    out.append(f"  Components    : {len(report.components)}")
    if report.output_path:
        out.append(f"  Written to    : {report.output_path}")
    out.append("")

    if report.components:
        out.append("  Top 25 components:")
        for c in sorted(report.components, key=lambda x: x.name)[:25]:
            lic = f" [{c.license}]" if c.license else ""
            out.append(f"    · {c.name} {c.version}{lic}")
        if len(report.components) > 25:
            out.append(f"    ... +{len(report.components) - 25} más")
        out.append("")

    out.append("  PASSED · SBOM generado correctamente")
    out.append("")
    return "\n".join(out)


def format_json(report: SbomReport) -> str:
    def ser(c: SbomComponent) -> dict:
        return {
            "name": c.name, "version": c.version,
            "purl": c.purl, "license": c.license,
        }

    return json.dumps({
        "root": report.root, "lang": report.lang,
        "bom_format": report.bom_format,
        "spec_version": report.spec_version,
        "scanner_available": report.scanner_available,
        "output_path": report.output_path,
        "error": report.error,
        "components_count": len(report.components),
        "components": [ser(c) for c in report.components],
    }, indent=2)
