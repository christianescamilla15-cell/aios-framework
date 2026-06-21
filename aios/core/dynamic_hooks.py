"""Dynamic analysis hooks · v2.8.0

Template para integrar runtime observability y testing con el flujo
estatico de AIOS. La literatura (IAST studies · JSAER 2023) muestra
que DAST/IAST encuentra ~15% adicional que SAST puro no puede ver por
Rice's theorem (race conditions · auth bypass dinamico · data flow
inter-servicio).

Este modulo NO corre tools dinamicos directamente (requieren setup
especifico del target: container · agent · eBPF probe). Provee:

1. **Integration test stub generator** · emite plantillas xUnit C# o
   pytest Python con asserts derivados de characterization fingerprints.
   Ayuda al developer a cubrir la superficie API real antes del refactor.

2. **Runtime trace markers** · helper para anotar puntos calientes del
   codigo con tags que un APM/observability stack (CloudWatch · DataDog ·
   OpenTelemetry) puede filtrar. No emite telemetria · solo sugiere
   donde insertar instrumentacion.

3. **IAST/eBPF hook config emit** · genera stub configs para Falco o
   Contrast IAST apuntando a endpoints/syscalls sospechosos detectados
   en el scan estatico (ej. SqlCommand.Execute, File.Read, etc).

CLI:
    aios dynamic-hooks generate-tests --characterization .aios/characterization
    aios dynamic-hooks emit-falco-config --findings findings.json

Esto es "hook" en sentido literal: no corre nada, prepara artefactos
para que el developer cierre el loop en CI/CD con tests reales.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class TestStub:
    target_class: str
    target_method: str
    language: str  # "csharp" · "python" · "java"
    test_body: str
    coverage_rationale: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FalcoRule:
    name: str
    condition: str  # Falco rule condition syntax
    output: str
    priority: str = "WARNING"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DynamicHooksReport:
    root: str
    test_stubs: list[TestStub] = field(default_factory=list)
    falco_rules: list[FalcoRule] = field(default_factory=list)
    instrumentation_points: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "test_stubs": [s.to_dict() for s in self.test_stubs],
            "falco_rules": [r.to_dict() for r in self.falco_rules],
            "instrumentation_points": self.instrumentation_points,
        }


# ---------------------------------------------------------------------------
# 1. Integration test stub generator
# ---------------------------------------------------------------------------

_XUNIT_TEMPLATE = """[Fact]
public void {method}_PreservesBehavior_Characterization()
{{
    // Auto-generated stub · characterization fingerprint
    // Target: {target_class}.{method} · {param_count} params
    // TODO · instanciar con dependencias reales o mocks
    // var sut = new {target_class}(/* deps */);
    // var result = sut.{method}(/* args */);
    // Assert.NotNull(result);
    // Assert.Equal(/* expected */, result);
    // {rationale}
    Assert.True(false, "Test stub pendiente · completar con caso real");
}}"""


_PYTEST_TEMPLATE = """def test_{method}_preserves_behavior_characterization():
    # Auto-generated stub · characterization fingerprint
    # Target: {target_class}.{method} · {param_count} params
    # TODO · instanciar con deps o mocks
    # sut = {target_class}(...)
    # result = sut.{method}(...)
    # assert result is not None
    # assert result == expected
    # {rationale}
    assert False, "Test stub pendiente · completar con caso real\""""


def generate_test_stubs(characterization_dir: Path,
                        max_methods_per_class: int = 5,
                        language: Optional[str] = None) -> list[TestStub]:
    """Para cada fingerprint .json en characterization_dir, emite
    stubs xUnit (C#) o pytest (Python) para sus metodos publicos.
    language=None auto-detecta de la extension."""
    stubs: list[TestStub] = []
    if not characterization_dir.exists():
        return stubs
    for fp in characterization_dir.glob("*.json"):
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        file_name = data.get("file", "")
        detected_lang = language or _detect_language(file_name)
        template = _XUNIT_TEMPLATE if detected_lang == "csharp" else _PYTEST_TEMPLATE
        classes = data.get("classes", []) or []
        # Fingerprint format: classes[] sin methods anidados + methods[] top-level
        primary_class = classes[0].get("name", "Unknown") if classes else "Unknown"
        methods = data.get("methods", []) or []
        public_methods = [
            m for m in methods
            if m.get("visibility", "public") == "public"
            and not m.get("name", "").startswith("_")
        ]
        for m in public_methods[:max_methods_per_class]:
            method_name = m.get("name", "Unknown")
            params = m.get("args", []) or m.get("params", []) or []
            body = template.format(
                target_class=primary_class,
                method=method_name,
                param_count=len(params),
                rationale=f"Preserva firma {len(params)}-param pre-refactor",
            )
            stubs.append(TestStub(
                target_class=primary_class,
                target_method=method_name,
                language=detected_lang,
                test_body=body,
                coverage_rationale=f"API publica detectada en "
                                   f"characterization · {file_name}",
            ))
    return stubs


def _detect_language(file_name: str) -> str:
    if file_name.endswith(".cs"):
        return "csharp"
    if file_name.endswith(".py"):
        return "python"
    if file_name.endswith(".java"):
        return "java"
    return "csharp"


# ---------------------------------------------------------------------------
# 2. Falco / eBPF rules emission desde findings
# ---------------------------------------------------------------------------

_FALCO_RULE_TEMPLATES = {
    "CWE-522": FalcoRule(
        name="Credential Plaintext in Memory",
        condition="evt.type in (read, open) and "
                  "fd.filename endswith '.config' and proc.name != 'vault-agent'",
        output="Config file with potential plaintext credential accessed "
               "(user=%user.name proc=%proc.name file=%fd.name)",
        priority="WARNING",
    ),
    "CWE-78": FalcoRule(
        name="Shell Command Execution by Service",
        condition="spawned_process and proc.name in (sh, bash, cmd, powershell) "
                  "and proc.pname in (noshow, fleet_ops_app, arc, bsp)",
        output="Service process spawning shell · possible command injection "
               "(parent=%proc.pname child=%proc.name cmd=%proc.cmdline)",
        priority="CRITICAL",
    ),
    "CWE-89": FalcoRule(
        name="Raw SQL from Concatenation",
        condition="evt.type = write and fd.name contains 'sql.log' and "
                  "evt.buffer contains 'OR 1=1'",
        output="SQL injection pattern detected in query log "
               "(file=%fd.name buffer=%evt.buffer)",
        priority="CRITICAL",
    ),
    "CWE-664": FalcoRule(
        name="Unusual InvalidOperationException Rate",
        condition="evt.type = write and fd.name contains 'app.log' and "
                  "evt.buffer contains 'InvalidOperationException'",
        output="Possible remove-in-iteration runtime failure "
               "(file=%fd.name buffer=%evt.buffer)",
        priority="WARNING",
    ),
}


def emit_falco_rules(findings: list[dict]) -> list[FalcoRule]:
    """Dado una lista de findings (ej. del security scan), emite reglas
    Falco para detectar el comportamiento en runtime."""
    rules: list[FalcoRule] = []
    seen_cwe: set[str] = set()
    for f in findings:
        cwe = (f.get("cwe") or "").split(",")[0].strip()
        if not cwe or cwe in seen_cwe:
            continue
        tmpl = _FALCO_RULE_TEMPLATES.get(cwe)
        if tmpl:
            rules.append(tmpl)
            seen_cwe.add(cwe)
    return rules


# ---------------------------------------------------------------------------
# 3. Instrumentation point suggestions
# ---------------------------------------------------------------------------

_INSTRUMENTATION_HOTSPOTS = [
    {"pattern": "SqlCommand.Execute",
     "otel_span": "db.sqlserver.query",
     "rationale": "Database call · monitor latency + errors"},
    {"pattern": "HttpClient.SendAsync",
     "otel_span": "http.client.request",
     "rationale": "External HTTP call · monitor retries + duration"},
    {"pattern": "SoapClient.",
     "otel_span": "rpc.soap.call",
     "rationale": "SOAP service call · monitor SLA + error rate"},
    {"pattern": "File.ReadAllText",
     "otel_span": "fs.read",
     "rationale": "File read · monitor IO latency · redact PII"},
    {"pattern": "SFTPAdapter.Upload",
     "otel_span": "sftp.upload",
     "rationale": "SFTP transfer · monitor size + success rate"},
]


def suggest_instrumentation(characterization_dir: Path) -> list[dict]:
    """Escanea characterization fingerprints buscando patterns hot-spot y
    sugiere puntos de instrumentacion OpenTelemetry."""
    suggestions: list[dict] = []
    if not characterization_dir.exists():
        return suggestions
    for fp in characterization_dir.glob("*.json"):
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        file_name = data.get("file", "")
        # Heuristic: check method names + class names against patterns
        classes = data.get("classes", []) or []
        for cls in classes:
            cls_name = cls.get("name", "")
            for m in cls.get("methods", []) or []:
                mn = m.get("name", "")
                full = f"{cls_name}.{mn}"
                for h in _INSTRUMENTATION_HOTSPOTS:
                    if h["pattern"].lower() in full.lower():
                        suggestions.append({
                            "file": file_name,
                            "target": full,
                            "otel_span": h["otel_span"],
                            "rationale": h["rationale"],
                        })
    return suggestions


# ---------------------------------------------------------------------------
# Public convenience
# ---------------------------------------------------------------------------

def generate_dynamic_hooks(root: Path,
                           characterization_dir: Optional[Path] = None,
                           findings: Optional[list[dict]] = None
                           ) -> DynamicHooksReport:
    """Orquesta los 3 hooks · retorna un reporte unificado."""
    root = Path(root).resolve()
    char_dir = characterization_dir or (root / ".aios" / "characterization")
    report = DynamicHooksReport(root=str(root))
    report.test_stubs = generate_test_stubs(char_dir)
    report.falco_rules = emit_falco_rules(findings or [])
    report.instrumentation_points = suggest_instrumentation(char_dir)
    return report
