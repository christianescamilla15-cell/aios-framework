"""Paridad contra un oráculo escrito a mano (tests/golden/detectores.json).

Por cada regla el oráculo trae un fragmento que DEBE dispararla y otro que NO. Tres niveles:

1. Por caso: el positivo dispara la regla y el negativo no (un archivo aislado por corrida).
2. Corpus completo: todas las reglas esperadas aparecen al escanear juntos los positivos (multiconjunto) y
   las cifras control (casos y reglas distintas) cuadran con el oráculo.
3. Control negativo: si se quita un positivo, la comparación lo detecta y nombra la regla faltante.

Además, la compuerta «regla → prueba»: todo detector de security_gate debe aparecer en alguna prueba.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import pytest

from aios.core import security_gate as sg
from aios.core.security_gate import scan_directory

ORACULO = json.loads((Path(__file__).parent / "golden" / "detectores.json").read_text(encoding="utf-8"))
CASOS = ORACULO["casos"]


def _reglas(directorio: Path) -> Counter:
    return Counter(f.rule_id for f in scan_directory(directorio))


def _faltantes(esperado: Counter, encontrado: Counter) -> Counter:
    """Reglas del oráculo que no aparecieron (o aparecieron menos veces). Vacío = paridad."""
    return esperado - encontrado


@pytest.mark.parametrize("caso", CASOS, ids=[c["regla"] for c in CASOS])
def test_positivo_dispara_y_negativo_no(tmp_path, caso):
    pos = tmp_path / "pos"
    neg = tmp_path / "neg"
    pos.mkdir()
    neg.mkdir()
    (pos / caso["archivo"]).write_text(caso["positivo"], encoding="utf-8")
    (neg / caso["archivo"]).write_text(caso["negativo"], encoding="utf-8")
    assert caso["regla"] in _reglas(pos), f"{caso['regla']} no disparó con su positivo"
    assert caso["regla"] not in _reglas(neg), f"{caso['regla']} disparó con su negativo"


def _corpus(destino: Path, omitir: str | None = None) -> Counter:
    """Escribe todos los positivos (uno por subdirectorio) y devuelve el multiconjunto esperado."""
    esperado: Counter = Counter()
    for i, caso in enumerate(CASOS):
        if caso["regla"] == omitir:
            continue
        sub = destino / f"{i:03d}"
        sub.mkdir(parents=True)
        (sub / caso["archivo"]).write_text(caso["positivo"], encoding="utf-8")
        esperado[caso["regla"]] += 1
    return esperado


def test_corpus_completo_cuadra_con_el_oraculo(tmp_path):
    esperado = _corpus(tmp_path)
    encontrado = _reglas(tmp_path)
    assert _faltantes(esperado, encontrado) == Counter()
    # cifras control del oráculo
    assert sum(esperado.values()) == len(CASOS)
    assert len(esperado) == len({c["regla"] for c in CASOS})


def test_control_negativo_la_comparacion_detecta_un_positivo_faltante(tmp_path):
    """Si el corpus pierde un caso, la paridad debe fallar y nombrar exactamente esa regla."""
    quitada = "STATIC-SQL-CONCAT"
    _corpus(tmp_path, omitir=quitada)
    esperado_completo = Counter(c["regla"] for c in CASOS)
    faltan = _faltantes(esperado_completo, _reglas(tmp_path))
    assert faltan == Counter({quitada: 1})


def test_oraculo_sin_duplicados_ni_reglas_inexistentes():
    reglas_detectores = {d[2] for d in sg._DETECTORS}
    reglas_oraculo = [c["regla"] for c in CASOS]
    assert len(reglas_oraculo) == len(set(reglas_oraculo))
    assert set(reglas_oraculo) <= reglas_detectores


def test_todo_detector_tiene_al_menos_una_prueba():
    """Compuerta regla → prueba: el identificador de cada detector aparece en alguna prueba o en el oráculo."""
    textos = "\n".join(p.read_text(encoding="utf-8") for p in Path(__file__).parent.glob("test_*.py"))
    cubiertas = set(re.findall(r"[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+", textos)) | {c["regla"] for c in CASOS}
    sin_prueba = sorted({d[2] for d in sg._DETECTORS} - cubiertas)
    assert sin_prueba == []
