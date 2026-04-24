"""Tests · v3.6.5 · G-22 SBOM CycloneDX generation wrap."""
from __future__ import annotations

import json
from pathlib import Path

from aios.core.sbom import (
    parse_cyclonedx_bom, write_sbom, format_human, format_json,
)


def _sample_cyclonedx_bom():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
            {
                "type": "library",
                "name": "urllib3",
                "version": "1.26.18",
                "purl": "pkg:pypi/urllib3@1.26.18",
                "licenses": [{"license": {"name": "MIT"}}],
            },
        ],
    }


def test_parse_cyclonedx_extracts_components():
    data = _sample_cyclonedx_bom()
    report = parse_cyclonedx_bom(data, root="/tmp/proj", lang="python")
    assert len(report.components) == 2
    names = [c.name for c in report.components]
    assert "requests" in names
    assert "urllib3" in names


def test_parse_cyclonedx_extracts_license():
    data = _sample_cyclonedx_bom()
    report = parse_cyclonedx_bom(data, root="/tmp/p", lang="python")
    licenses = {c.name: c.license for c in report.components}
    assert licenses["requests"] == "Apache-2.0"
    assert licenses["urllib3"] == "MIT"  # from "name" not "id"


def test_parse_cyclonedx_extracts_spec_version():
    data = _sample_cyclonedx_bom()
    report = parse_cyclonedx_bom(data, root="/tmp/p", lang="python")
    assert report.bom_format == "CycloneDX"
    assert report.spec_version == "1.5"


def test_sbom_skip_when_not_available():
    data = {"scanner_available": False, "error": "cyclonedx-py not found"}
    report = parse_cyclonedx_bom(data, root="/tmp/p", lang="python")
    assert report.scanner_available is False
    assert report.components == []


def test_write_sbom_creates_file(tmp_path):
    data = _sample_cyclonedx_bom()
    report = parse_cyclonedx_bom(data, root=str(tmp_path), lang="python")
    output = tmp_path / "sbom.cdx.json"
    report2 = write_sbom(report, output)
    assert output.exists()
    assert report2.output_path == str(output)
    written = json.loads(output.read_text())
    assert written["bomFormat"] == "CycloneDX"
    assert len(written["components"]) == 2


def test_format_human_lists_components():
    data = _sample_cyclonedx_bom()
    report = parse_cyclonedx_bom(data, root="/tmp/p", lang="python")
    out = format_human(report)
    assert "requests" in out
    assert "urllib3" in out
    assert "Apache-2.0" in out


def test_format_json_serializable():
    data = _sample_cyclonedx_bom()
    report = parse_cyclonedx_bom(data, root="/tmp/p", lang="python")
    parsed = json.loads(format_json(report))
    assert parsed["components_count"] == 2
    assert parsed["scanner_available"] is True


def test_parse_cyclonedx_handles_empty_components():
    data = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    report = parse_cyclonedx_bom(data, root="/tmp/p", lang="python")
    assert report.components == []
    assert report.scanner_available is True
