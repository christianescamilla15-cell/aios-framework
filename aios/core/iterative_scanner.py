"""Iterative Multi-Strategy Scanner · v3.2.0

Diseño: saturation loop · cada iteracion usa una ESTRATEGIA DISTINTA y
se detiene cuando la proxima iteracion no aporta mas de `min_delta`
findings nuevos vs los acumulados.

Por que NO es un pure re-run loop:
- Los detectores regex son deterministas · iter2 == iter1 sobre mismo
  codigo = waste de compute.
- La ganancia real viene de APLICAR TECNICAS DISTINTAS que capturan
  clases ortogonales de bugs.

Estrategias disponibles (orden canónico):
1. regex           · 77 detectores security_gate v3.1
2. ensemble        · OSS tools externos (semgrep · bandit · trivy · etc)
3. llm_deep_review · Opus/Sonnet/Haiku/Ollama sobre archivos top-severity
4. cross_file_taint · lightweight grep-based variable flow (credencial
                      asignada en A.cs → usada en B.cs)
5. pattern_discovery · LLM propone regex nuevas desde corpus observado
                      (dry-run · requiere ratificacion humana)

Uso canónico:
    scanner = IterativeScanner(
        root=Path("."),
        strategies=["regex", "ensemble", "llm_deep_review"],
        max_iterations=5,
        min_delta=2,
    )
    report = scanner.run()
    print(f"Converged in {report.iterations_run} iterations")
    print(f"Total findings: {len(report.all_findings)}")

CLI:
    aios iterate --root . --strategies regex,ensemble,llm_deep_review
                 --max-iterations 5 --min-delta 2 --format json
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Optional


@dataclass
class IterativeFinding:
    """Finding normalizado · clave para dedup cross-strategy."""
    file: str
    line: int
    rule_id: str
    severity: str
    cwe: str = ""
    message: str = ""
    strategy: str = ""  # cual estrategia lo genero primero

    def dedup_key(self) -> tuple[str, int, str]:
        return (self.file, self.line, self.rule_id)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IterationResult:
    iteration: int
    strategy: str
    started_at: str
    duration_sec: float
    findings_in_iteration: int
    new_findings_this_iteration: int
    cumulative_findings: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IterativeReport:
    root: str
    strategies_configured: list[str]
    max_iterations: int
    min_delta: int
    iterations_run: int
    converged: bool
    stop_reason: str
    per_iteration: list[IterationResult] = field(default_factory=list)
    all_findings: list[IterativeFinding] = field(default_factory=list)

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.all_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def by_strategy(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.all_findings:
            counts[f.strategy] = counts.get(f.strategy, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "strategies_configured": self.strategies_configured,
            "max_iterations": self.max_iterations,
            "min_delta": self.min_delta,
            "iterations_run": self.iterations_run,
            "converged": self.converged,
            "stop_reason": self.stop_reason,
            "per_iteration": [it.to_dict() for it in self.per_iteration],
            "by_severity": self.by_severity(),
            "by_strategy": self.by_strategy(),
            "findings": [f.to_dict() for f in self.all_findings],
        }


# ---------------------------------------------------------------------------
# Strategy implementations
# ---------------------------------------------------------------------------

def _strategy_regex(root: Path,
                    known: set,
                    config: dict) -> list[IterativeFinding]:
    """Corre security_gate v3.1.x scan_directory y normaliza findings."""
    from aios.core.security_gate import scan_directory, _load_config
    cfg = _load_config(root)
    raw = scan_directory(root, cfg)
    findings: list[IterativeFinding] = []
    for f in raw or []:
        findings.append(IterativeFinding(
            file=getattr(f, "file", ""),
            line=int(getattr(f, "line", 0) or 0),
            rule_id=getattr(f, "rule_id", ""),
            severity=getattr(f, "severity", ""),
            cwe=getattr(f, "cwe", ""),
            message=getattr(f, "description", "") or getattr(f, "snippet", ""),
            strategy="regex",
        ))
    return findings


def _strategy_ensemble(root: Path,
                       known: set,
                       config: dict) -> list[IterativeFinding]:
    """Corre ensemble de OSS tools disponibles."""
    from aios.core.ensemble_scanner import run_ensemble
    tools = config.get("ensemble_tools")
    report = run_ensemble(root, tools=tools)
    findings: list[IterativeFinding] = []
    for f in report.findings:
        findings.append(IterativeFinding(
            file=f.file,
            line=f.line,
            rule_id=f"ensemble:{f.tool}:{f.rule_id}",
            severity=f.severity,
            cwe=f.cwe,
            message=f.message,
            strategy="ensemble",
        ))
    return findings


def _strategy_llm_deep_review(root: Path,
                              known: set,
                              config: dict) -> list[IterativeFinding]:
    """Envia los N archivos top-severity a LLM pidiendo issues que el
    scanner no detecto. Configurable con provider/model via config."""
    # Seleccionar archivos top-severity basado en known findings
    file_severity: dict[str, int] = {}
    for f_tup in known:
        file_path, _line, _rid = f_tup
        # 'known' solo tiene dedup keys · sin severity · usar uniform weight
        file_severity[file_path] = file_severity.get(file_path, 0) + 1
    top_files = sorted(
        file_severity.items(), key=lambda x: -x[1]
    )[:config.get("llm_max_files", 5)]
    if not top_files:
        # Fallback · primeros 5 archivos fuente del repo
        exts = {".cs", ".py", ".java", ".js", ".ts"}
        candidates = [
            p for p in root.rglob("*")
            if p.is_file() and p.suffix in exts
            and not any(part in p.parts for part in
                        (".git", "bin", "obj", ".vs", "node_modules"))
        ][:5]
        top_files = [(str(p.relative_to(root)), 0) for p in candidates]

    provider = config.get("llm_provider", "ollama")
    model = config.get("llm_model", "gemma3:latest")
    host = config.get("ollama_host", "http://localhost:11434")

    findings: list[IterativeFinding] = []
    for file_rel, _score in top_files:
        file_path = root / file_rel
        if not file_path.exists():
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        content = content[:8000]  # cap bytes per LLM call
        prompt = _build_deep_review_prompt(file_rel, content)
        response = _call_llm(provider, model, host, prompt,
                             timeout=config.get("llm_timeout", 120))
        parsed = _parse_deep_review_response(response, file_rel)
        for p in parsed:
            findings.append(IterativeFinding(
                file=file_rel,
                line=p.get("line", 0),
                rule_id=f"llm:deep-review:{p.get('cwe','unknown')}",
                severity=p.get("severity", "MEDIUM"),
                cwe=p.get("cwe", ""),
                message=p.get("issue", "")[:300],
                strategy="llm_deep_review",
            ))
    return findings


def _build_deep_review_prompt(file_rel: str, content: str) -> str:
    return f"""Eres un security auditor senior. Revisa el archivo adjunto y
encuentra issues que un scanner regex-based NO detectaría: logs con PII,
race conditions, host key verification missing, stack trace disclosure,
recursion sin max depth, error swallowing, singleton sin thread-safety.

Archivo: {file_rel}

```
{content}
```

Responde JSON array (sin markdown fences · sin texto extra):
[
  {{"line": 42, "severity": "HIGH", "cwe": "CWE-532", "issue": "..."}},
  ...
]

Si no encuentras nada · responde `[]`. Max 10 issues."""


def _call_llm(provider: str, model: str, host: str,
              prompt: str, timeout: int = 120) -> str:
    if provider == "ollama":
        try:
            import urllib.request
            req = urllib.request.Request(
                f"{host}/api/generate",
                data=json.dumps({
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", "")
        except Exception:  # noqa: BLE001
            return "[]"  # fall back to no-findings
    if provider == "anthropic":
        try:
            import urllib.request
            import os
            key = os.environ.get("ANTHROPIC_API_KEY", "")
            if not key:
                return "[]"
            body = json.dumps({
                "model": model,
                "max_tokens": 2048,
                "messages": [{"role": "user", "content": prompt}],
            }).encode("utf-8")
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            # Anthropic returns: { content: [{type:text, text:...}] }
            blocks = data.get("content", [])
            if blocks and isinstance(blocks, list):
                return blocks[0].get("text", "")
        except Exception:  # noqa: BLE001
            return "[]"
    return "[]"


def _parse_deep_review_response(raw: str, file_rel: str) -> list[dict]:
    """Parsea JSON array · graceful degrade a []."""
    if not raw:
        return []
    text = raw.strip()
    # Strip markdown fences si las hay
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    # Extrae primer array plausible
    m = re.search(r"\[.*\]", text, re.DOTALL)
    if m:
        text = m.group(0)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    out: list[dict] = []
    for item in data[:20]:
        if not isinstance(item, dict):
            continue
        out.append({
            "line": int(item.get("line", 0) or 0),
            "severity": str(item.get("severity", "MEDIUM")).upper(),
            "cwe": str(item.get("cwe", "")),
            "issue": str(item.get("issue", ""))[:300],
        })
    return out


def _strategy_cross_file_taint(root: Path,
                               known: set,
                               config: dict) -> list[IterativeFinding]:
    """Cross-file taint · grep lightweight · busca credenciales/secretos
    asignados en archivo A usados en archivo B."""
    findings: list[IterativeFinding] = []
    # Buscar patrones `var X = "plaintext"` seguidos en otro archivo
    # `methodCall(X)` o `someClient.Connect(X)`.
    # Implementacion simple: regex en 2 pasadas.

    _DEFAULT_EXCLUDES = {"bin", "obj", ".vs", ".vscode", ".git",
                         "node_modules", "packages", "__pycache__"}
    _EXTS = {".cs", ".py", ".java", ".js", ".ts"}

    # Pasada 1 · extrae asignaciones credential-like
    cred_pat = re.compile(
        r"""(?:string|var|const|private|public)\s+"""
        r"""(\w*(?:password|secret|token|key|credential)\w*)\s*=\s*"""
        r"""["']([^"'\n]{4,})["']""",
        re.IGNORECASE,
    )
    assignments: dict[str, list[dict]] = {}  # var_name -> [{file, line, value}]
    for fp in root.rglob("*"):
        if not fp.is_file():
            continue
        if fp.suffix not in _EXTS:
            continue
        if any(part in _DEFAULT_EXCLUDES for part in fp.parts):
            continue
        try:
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        for m in cred_pat.finditer(content):
            var_name = m.group(1)
            value = m.group(2)
            line_no = content.count("\n", 0, m.start()) + 1
            rel = str(fp.relative_to(root))
            assignments.setdefault(var_name, []).append({
                "file": rel, "line": line_no, "value": value,
            })

    # Pasada 2 · busca usage `.Connect(X)` · `.SendEmail(..., X)` en otros files
    for var_name, assigns in assignments.items():
        if len(assigns) == 0:
            continue
        # Primero flag la asignacion como suspicious
        for a in assigns:
            findings.append(IterativeFinding(
                file=a["file"],
                line=a["line"],
                rule_id="cross-file-taint:credential-assignment",
                severity="MEDIUM",
                cwe="CWE-798",
                message=f"Variable '{var_name}' asignada con literal plaintext · "
                        f"verificar que flujo no llegue a logs o outbound",
                strategy="cross_file_taint",
            ))
        # Busca usage del var en archivos distintos
        usage_pat = re.compile(
            rf"""\b\w*\.(?:Connect|Authenticate|SendEmail|UploadFile|"""
            rf"""Post|Put|Get|Log\w*)\s*\([^)]*\b{re.escape(var_name)}\b""",
            re.IGNORECASE,
        )
        assigned_files = {a["file"] for a in assigns}
        for fp in root.rglob("*"):
            if not fp.is_file():
                continue
            if fp.suffix not in _EXTS:
                continue
            if any(part in _DEFAULT_EXCLUDES for part in fp.parts):
                continue
            rel = str(fp.relative_to(root))
            if rel in assigned_files:
                continue  # same file, ya flagged
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue
            for m in usage_pat.finditer(content):
                line_no = content.count("\n", 0, m.start()) + 1
                findings.append(IterativeFinding(
                    file=rel,
                    line=line_no,
                    rule_id=f"cross-file-taint:usage:{var_name}",
                    severity="HIGH",
                    cwe="CWE-200",
                    message=f"Variable '{var_name}' asignada plaintext en "
                            f"{assigned_files} se usa aqui en Connect/Send/Log · "
                            f"taint flow de credencial cross-file",
                    strategy="cross_file_taint",
                ))
    return findings


_STRATEGIES: dict[str, Callable] = {
    "regex": _strategy_regex,
    "ensemble": _strategy_ensemble,
    "llm_deep_review": _strategy_llm_deep_review,
    "cross_file_taint": _strategy_cross_file_taint,
}


def available_strategies() -> list[str]:
    return list(_STRATEGIES.keys())


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

class IterativeScanner:
    """Orquesta multi-strategy saturation loop."""

    def __init__(
        self,
        root: Path,
        strategies: list[str],
        max_iterations: int = 5,
        min_delta: int = 2,
        config: Optional[dict] = None,
    ):
        self.root = Path(root).resolve()
        self.strategies = strategies
        self.max_iterations = max_iterations
        self.min_delta = min_delta
        self.config = config or {}

    def run(self) -> IterativeReport:
        import time
        from datetime import datetime, timezone

        report = IterativeReport(
            root=str(self.root),
            strategies_configured=self.strategies,
            max_iterations=self.max_iterations,
            min_delta=self.min_delta,
            iterations_run=0,
            converged=False,
            stop_reason="",
        )
        dedup: set = set()
        all_findings: dict = {}  # dedup_key -> IterativeFinding (first seen)

        for i, strategy_name in enumerate(self.strategies[:self.max_iterations], 1):
            runner = _STRATEGIES.get(strategy_name)
            if not runner:
                report.per_iteration.append(IterationResult(
                    iteration=i, strategy=strategy_name,
                    started_at=datetime.now(timezone.utc).isoformat(),
                    duration_sec=0.0,
                    findings_in_iteration=0,
                    new_findings_this_iteration=0,
                    cumulative_findings=len(dedup),
                ))
                continue
            t0 = time.time()
            started = datetime.now(timezone.utc).isoformat()
            try:
                found = runner(self.root, dedup, self.config)
            except Exception as exc:  # noqa: BLE001
                found = []
                report.stop_reason = f"strategy {strategy_name} error: {exc}"
            duration = time.time() - t0
            new_count = 0
            for f in found:
                k = f.dedup_key()
                if k not in dedup:
                    dedup.add(k)
                    all_findings[k] = f
                    new_count += 1
            report.per_iteration.append(IterationResult(
                iteration=i, strategy=strategy_name,
                started_at=started,
                duration_sec=round(duration, 2),
                findings_in_iteration=len(found),
                new_findings_this_iteration=new_count,
                cumulative_findings=len(dedup),
            ))
            report.iterations_run = i
            # Check saturation · only stop if we're past first iteration
            if i > 1 and new_count < self.min_delta:
                report.converged = True
                report.stop_reason = (
                    f"Saturation · iteration {i} aportó {new_count} < "
                    f"min_delta={self.min_delta}"
                )
                break

        if not report.stop_reason:
            if report.iterations_run >= self.max_iterations:
                report.stop_reason = f"Max iterations ({self.max_iterations}) reached"
            elif report.iterations_run == len(self.strategies):
                report.stop_reason = "All strategies exhausted"

        # v3.3.1 · advertencia operativa cuando solo 1 estrategia fue
        # productiva · indica que faltan tools o LLM para multi-strategy
        # real. Detecta el caso gotcha del user: iterate con regex solo
        # satura en iter 1 porque ensemble/taint/LLM no aportan.
        productive = sum(
            1 for it in report.per_iteration
            if it.new_findings_this_iteration > 0
        )
        if productive <= 1 and report.iterations_run > 1:
            hints = []
            if "ensemble" in self.strategies:
                hints.append("instalar semgrep/gitleaks/trufflehog "
                             "(`pip install semgrep bandit` o brew)")
            if "llm_deep_review" in self.strategies:
                hints.append("activar llm_classifier en aios-config.json "
                             "o exportar ANTHROPIC_API_KEY")
            if "cross_file_taint" in self.strategies:
                hints.append("cross_file_taint solo dispara sobre "
                             "credenciales hardcoded en source · "
                             "no aplica a configs externas")
            if hints:
                report.stop_reason += (
                    f" · solo {productive} estrategia productiva · "
                    f"para multi-strategy real: " + " · ".join(hints)
                )

        report.all_findings = list(all_findings.values())
        return report


def run_iterative(
    root: Path,
    strategies: Optional[list[str]] = None,
    max_iterations: int = 5,
    min_delta: int = 2,
    config: Optional[dict] = None,
) -> IterativeReport:
    """Convenience · alias del constructor + run()."""
    strategies = strategies or ["regex", "ensemble", "cross_file_taint"]
    return IterativeScanner(
        root, strategies, max_iterations, min_delta, config
    ).run()
