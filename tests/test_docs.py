"""La documentación que actúa como compuerta no puede apuntar a pruebas que no existen."""
from __future__ import annotations

import re
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]


def test_reglas_md_only_references_existing_tests():
    texto = (RAIZ / "docs" / "reglas.md").read_text(encoding="utf-8")
    refs = re.findall(r"`(tests/[\w/]+\.py)(?:::(\w+))?`", texto)
    assert len(refs) >= 50
    faltan = []
    for archivo, funcion in refs:
        ruta = RAIZ / archivo
        if not ruta.exists():
            faltan.append(archivo)
        elif funcion and not re.search(rf"^def {funcion}\(", ruta.read_text(encoding="utf-8"), re.M):
            faltan.append(f"{archivo}::{funcion}")
    assert faltan == []


def test_adrs_declare_state_context_decision_and_consequences():
    for adr in sorted((RAIZ / "docs" / "adr").glob("0*.md")):
        texto = adr.read_text(encoding="utf-8")
        for seccion in ("Estado:", "## Contexto", "## Decisión", "## Consecuencias"):
            assert seccion in texto, f"{adr.name}: falta {seccion}"
