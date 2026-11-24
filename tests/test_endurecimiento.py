"""Endurecimientos de seguridad (entradas no confiables): cada uno con su prueba de regresión."""
from __future__ import annotations

import pytest

LAUGHS = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]>\n'
)


def test_stack_checks_reject_unknown_stack_without_importing(tmp_path):
    """Sólo se importan stacks de la lista blanca: un nombre arbitrario no llega a import_module."""
    from aios.core.module_loader import run_stack_checks

    result = run_stack_checks("os", tmp_path)
    assert result == [{"check": "Stack 'os'", "status": "fail", "detail": "stack desconocido"}]


def test_stack_info_for_unknown_stack_is_inert():
    from aios.core.module_loader import get_stack_info

    assert get_stack_info("../../etc") == {"id": "../../etc", "name": "../../etc"}


def test_slack_webhook_must_be_http(monkeypatch):
    """Un webhook file:// o ftp:// no se abre (urlopen leería archivos locales)."""
    import urllib.request

    from aios.core.notifications import send_slack

    def boom(*a, **k):  # pragma: no cover - si se llama, la prueba falla
        raise AssertionError("urlopen no debió llamarse")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    result = send_slack("file:///etc/passwd", "hola")
    assert result.sent is False
    assert "http" in result.detail


def test_ollama_host_must_be_http():
    from aios.core.llm_classifier import OllamaProvider

    with pytest.raises(ValueError, match="http"):
        OllamaProvider(host="file:///etc/passwd")
    assert OllamaProvider(host="http://localhost:11434/").host == "http://localhost:11434"


def test_coverage_xml_with_entities_is_rejected(tmp_path):
    """El XML de cobertura viene de herramientas externas: DTD con entidades = rechazo, no expansión."""
    from defusedxml import DefusedXmlException

    from aios.core.coverage_gate import parse_cobertura

    xml = tmp_path / "coverage.cobertura.xml"
    xml.write_text(LAUGHS + '<coverage line-rate="&lol2;"></coverage>\n', encoding="utf-8")
    with pytest.raises(DefusedXmlException):
        parse_cobertura(xml)


def test_drift_config_with_entities_falls_back_to_regex(tmp_path):
    """Un .config del repo escaneado con entidades no se expande: se usa el parser por regex."""
    from aios.core.drift_detector import _parse_xml_config

    cfg = tmp_path / "Web.config"
    cfg.write_text(
        LAUGHS + '<configuration><appSettings>'
        '<add key="Endpoint" value="https://api.example.com"/>'
        '</appSettings><x>&lol2;</x></configuration>\n',
        encoding="utf-8",
    )
    values = {kv.key: kv.value for kv in _parse_xml_config(cfg)}
    assert values.get("Endpoint") == "https://api.example.com"
    assert not any("lollol" in v for v in values.values())
