"""Tests · Kiro integration · skills markdown + vscode extension manifest.

Valida que los archivos de integracion con Kiro/VSCode esten bien
formados · no ejecuta la extension (TypeScript build es separado).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parents[1]


# ── VSCode extension manifest ────────────────────────────────────────

def test_vscode_package_json_parses():
    pkg = _REPO / "vscode-extension" / "package.json"
    assert pkg.exists()
    data = json.loads(pkg.read_text(encoding="utf-8"))
    assert data["name"] == "aios-vscode"
    assert "contributes" in data
    assert "commands" in data["contributes"]


def test_vscode_has_new_security_commands():
    """Post-integracion · los 5 comandos de security deben estar."""
    pkg = _REPO / "vscode-extension" / "package.json"
    data = json.loads(pkg.read_text(encoding="utf-8"))
    cmd_ids = {c["command"] for c in data["contributes"]["commands"]}
    expected = {
        "aios.arena", "aios.arenaList", "aios.engagement",
        "aios.engagementList", "aios.report",
    }
    assert expected <= cmd_ids, f"missing: {expected - cmd_ids}"


def test_vscode_commands_have_unique_ids():
    pkg = _REPO / "vscode-extension" / "package.json"
    data = json.loads(pkg.read_text(encoding="utf-8"))
    cmd_ids = [c["command"] for c in data["contributes"]["commands"]]
    assert len(cmd_ids) == len(set(cmd_ids)), "duplicate command IDs"


def test_vscode_security_commands_have_category():
    pkg = _REPO / "vscode-extension" / "package.json"
    data = json.loads(pkg.read_text(encoding="utf-8"))
    for cmd in data["contributes"]["commands"]:
        if cmd["command"] in (
            "aios.arena", "aios.arenaList", "aios.engagement",
            "aios.engagementList", "aios.report",
        ):
            assert "Security" in cmd["category"], (
                f"{cmd['command']} sin categoria Security"
            )


def test_vscode_extension_ts_has_handlers():
    """extension.ts debe declarar funcion handler por cada comando nuevo."""
    src = (_REPO / "vscode-extension" / "src" / "extension.ts").read_text()
    for handler in (
        "async function cmdArena(",
        "async function cmdArenaList(",
        "async function cmdEngagement(",
        "async function cmdEngagementList(",
        "async function cmdReport(",
    ):
        assert handler in src, f"handler no encontrado: {handler}"


# ── Kiro skills markdown ─────────────────────────────────────────────

_FRONTMATTER_RE = re.compile(
    r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL,
)


def _parse_frontmatter(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}
    out: dict = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip().strip('"')
    return out


def test_new_security_skills_exist():
    commands_dir = _REPO / "commands"
    for skill in (
        "security-scan-release.md",
        "arena-selfplay.md",
        "nemesis-engagement.md",
        "aios-report.md",
    ):
        assert (commands_dir / skill).exists(), f"missing skill {skill}"


def test_security_skills_have_description_and_triggers():
    for skill_name in (
        "security-scan-release.md",
        "arena-selfplay.md",
        "nemesis-engagement.md",
        "aios-report.md",
    ):
        skill = _REPO / "commands" / skill_name
        text = skill.read_text(encoding="utf-8")
        assert text.startswith("---"), f"{skill_name} sin frontmatter"
        fm = _parse_frontmatter(skill)
        assert fm.get("description"), f"{skill_name} sin description"
        # triggers es lista multilinea · verifica que exista el key
        assert "triggers:" in text.split("---")[1], (
            f"{skill_name} sin triggers"
        )


def test_skills_mention_aios_cli_commands():
    """Cada skill debe contener un comando `aios <subcmd>` ejecutable."""
    pairs = {
        "security-scan-release.md": "aios release",
        "arena-selfplay.md": "aios arena",
        "nemesis-engagement.md": "aios engagement",
        "aios-report.md": "aios report",
    }
    for skill_name, cmd in pairs.items():
        text = (_REPO / "commands" / skill_name).read_text(encoding="utf-8")
        assert cmd in text, f"{skill_name} no menciona `{cmd}`"


def test_kiro_bridge_module_importable():
    """kiro_bridge sigue funcional tras cambios."""
    from aios.core.kiro_bridge import generate_kiro_steering, generate_kiro_specs
    assert callable(generate_kiro_steering)
    assert callable(generate_kiro_specs)
