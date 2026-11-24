"""El wheel debe llevar todo archivo de datos que el paquete lee en tiempo de ejecución."""
from __future__ import annotations

import tomllib
from fnmatch import fnmatch
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]


def test_package_data_covers_every_runtime_data_file():
    config = tomllib.loads((RAIZ / "pyproject.toml").read_text(encoding="utf-8"))
    globs = config["tool"]["setuptools"]["package-data"]["aios"]
    datos = [
        p.relative_to(RAIZ / "aios").as_posix()
        for p in (RAIZ / "aios").rglob("*")
        if p.is_file() and p.suffix not in {".py", ".pyc"} and "__pycache__" not in p.parts
    ]
    assert datos, "se esperaban reglas YAML, plantillas y Markdown dentro de aios/"
    # fnmatch con «**/*.ext» exige un directorio: basta comparar la extensión de cada glob
    sin_cubrir = [d for d in datos if not any(fnmatch(d, g) or fnmatch(d, g.replace("**/", "")) for g in globs)]
    assert sin_cubrir == []


def test_governance_rules_and_templates_are_inside_the_package():
    gobierno = RAIZ / "aios" / "governance"
    assert {p.name for p in (gobierno / "rules").glob("*.yaml")} == {
        "tiers.yaml", "naming.yaml", "approvals.yaml", "stakeholders.yaml",
    }
    assert len(list((gobierno / "templates").glob("*.j2"))) == 6
