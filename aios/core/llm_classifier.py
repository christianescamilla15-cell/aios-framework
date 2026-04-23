"""LLM Classifier · v1.9.0 · RFC-003 Nivel 2

Clasifica findings que el Nivel 1 (ontology) marcó como `unclear` o
`pause_for_review` · usando un LLM call con context gathering:
- Surrounding code (±10 líneas)
- Git blame del line (autor · fecha · commit message)
- Cross-file occurrences (otras apariciones del mismo literal/pattern)
- Variable name context

Output del LLM · JSON estructurado:
- classification · bug | business_rule | migration_candidate | unclear
- confidence · 0.0 - 1.0
- reasoning · 1-2 sentences
- evidence · list of signals
- recommended_action

Providers soportados:
- mock · para tests · no llama API (retorna respuesta determinista)
- anthropic · Claude API (default · mejor reasoning)
- openai · GPT-4 family
- azure · Azure OpenAI (enterprise AMX)
- ollama · local models · zero-cost · privacidad

Uso canónico:
    classifier = LLMClassifier.from_config(cfg['security_gate']['llm_classifier'])
    result = classifier.classify(finding, root)
    if result.confidence >= 0.8:
        # Override la decisión del Nivel 1
        finding.ontology_action = result.recommended_action

Budget cap + caché son obligatorios (evitar gastar créditos infinitos).

Deriva de RFC-003 Nivel 2 · BACKLOG · feedback LM-FRK70K 2026-04-22.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Result + Config dataclasses
# ---------------------------------------------------------------------------

@dataclass
class LLMClassificationResult:
    """Resultado del LLM classifier."""
    classification: str  # bug | business_rule | migration_candidate | unclear
    confidence: float  # 0.0 - 1.0
    reasoning: str
    evidence: list[str] = field(default_factory=list)
    recommended_action: str = "pause_for_review"  # auto_fix | pause_for_review | human_required
    provider: str = "unknown"
    model: str = "unknown"
    cached: bool = False


# Classifications válidas (consistent con ontology.py)
VALID_CLASSIFICATIONS = ("bug", "business_rule", "migration_candidate", "unclear")
VALID_ACTIONS = ("auto_fix", "pause_for_review", "human_required", "skip", "warn")


# ---------------------------------------------------------------------------
# Context gathering
# ---------------------------------------------------------------------------

def gather_context(finding: object, root: Path,
                   window: int = 10,
                   max_cross_file: int = 5) -> dict:
    """Recolecta contexto alrededor del finding para feed al LLM.

    v2.7.0: agrega behavior_fingerprint (characterization hint) + ontology
    summary como contexto adicional para chain-of-thought.

    Args:
        finding: objeto con attrs rule_id · snippet · file · line
        root: directorio raíz del workspace
        window: líneas de contexto alrededor del finding
        max_cross_file: max otras ocurrencias del pattern a incluir
    """
    ctx = {
        "rule_id": getattr(finding, "rule_id", ""),
        "severity": getattr(finding, "severity", ""),
        "cwe": getattr(finding, "cwe", ""),
        "file": getattr(finding, "file", ""),
        "line": getattr(finding, "line", 0),
        "snippet": getattr(finding, "snippet", ""),
    }
    ctx["surrounding_code"] = _get_surrounding_lines(
        root, ctx["file"], ctx["line"], window
    )
    ctx["git_blame"] = _get_git_blame(root, ctx["file"], ctx["line"])
    ctx["cross_file_occurrences"] = _find_cross_file(
        root, ctx["snippet"], ctx["file"], max_cross_file
    )
    ctx["variable_names"] = _extract_variable_names(ctx["snippet"])
    # v2.7.0 RAG: characterization fingerprint + ontology summary
    ctx["behavior_fingerprint"] = _load_behavior_fingerprint(
        root, ctx["file"])
    ctx["ontology_hint"] = getattr(finding, "ontology_classification", "") or \
        getattr(finding, "ontology_message", "")
    return ctx


def _load_behavior_fingerprint(root: Path, file_rel: str) -> str:
    """v2.7.0 · lee characterization fingerprint si existe, como RAG context.
    Retorna string de 200-300 chars con metodos/clases detectados · vacio
    si no hay fingerprint."""
    if not file_rel:
        return ""
    # characterization files estan en .aios/characterization/<file-flat>.json
    flat = file_rel.replace("/", "__").replace("\\", "__")
    fp = root / ".aios" / "characterization" / f"{flat}.json"
    if not fp.exists():
        return ""
    try:
        data = json.loads(fp.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    classes = data.get("classes", []) or []
    methods_top: list[str] = []
    for c in classes[:3]:
        name = c.get("name", "?")
        meths = c.get("methods", [])[:3]
        for m in meths:
            methods_top.append(f"{name}.{m.get('name','?')}"
                               f"({len(m.get('params', []))} params)")
    return "; ".join(methods_top[:6])[:300]


def _get_surrounding_lines(root: Path, file_rel: str,
                           line: int, window: int) -> str:
    """Extrae ±window líneas alrededor de line para contexto."""
    try:
        fp = (root / file_rel) if not Path(file_rel).is_absolute() else Path(file_rel)
        if not fp.exists():
            return ""
        lines = fp.read_text(encoding="utf-8", errors="ignore").splitlines()
        start = max(0, line - 1 - window)
        end = min(len(lines), line + window)
        context_lines = []
        for i in range(start, end):
            marker = ">>>" if i + 1 == line else "   "
            context_lines.append(f"{marker} {i+1:4d}: {lines[i]}")
        return "\n".join(context_lines)
    except (OSError, UnicodeDecodeError):
        return ""


def _get_git_blame(root: Path, file_rel: str, line: int) -> dict:
    """Ejecuta git blame para obtener autor + commit + mensaje.
    Graceful degrade si no está en repo git o git no está disponible.
    """
    if not file_rel or line <= 0:
        return {}
    try:
        result = subprocess.run(
            ["git", "blame", "-L", f"{line},{line}", "--porcelain", file_rel],
            capture_output=True, text=True, cwd=str(root),
            timeout=10, check=False,
        )
        if result.returncode != 0:
            return {}
        blame_text = result.stdout
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        return {}

    blame: dict[str, str] = {}
    if blame_text:
        first_line = blame_text.split("\n", 1)[0]
        parts = first_line.split()
        if parts:
            blame["commit"] = parts[0][:12]
        for ln in blame_text.splitlines():
            if ln.startswith("author "):
                blame["author"] = ln[len("author "):].strip()
            elif ln.startswith("author-time "):
                try:
                    import datetime as dt
                    ts = int(ln[len("author-time "):].strip())
                    blame["date"] = dt.datetime.fromtimestamp(ts).strftime(
                        "%Y-%m-%d"
                    )
                except (ValueError, OSError):
                    pass
            elif ln.startswith("summary "):
                blame["summary"] = ln[len("summary "):].strip()
    return blame


def _find_cross_file(root: Path, snippet: str, current_file: str,
                     max_count: int) -> list[dict]:
    """Busca otras ocurrencias del snippet en el workspace.
    Usa grep si disponible · fallback a rglob · limitado a max_count.
    """
    if not snippet or len(snippet) < 4:
        return []
    # Extraer token más distintivo del snippet (literal entre comillas, etc.)
    token = _extract_distinctive_token(snippet)
    if not token:
        return []
    results: list[dict] = []
    try:
        cmd_result = subprocess.run(
            ["grep", "-rn", "--include=*.cs", "--include=*.py",
             "--include=*.java", "--include=*.php", "--include=*.cbl",
             "--include=*.config", "--include=*.xml", "-F", token, str(root)],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if cmd_result.returncode in (0, 1):
            for line in cmd_result.stdout.splitlines():
                if len(results) >= max_count:
                    break
                parts = line.split(":", 2)
                if len(parts) >= 3:
                    path_str, line_no, content = parts[0], parts[1], parts[2]
                    rel = path_str.replace(str(root) + "/", "").replace(
                        str(root) + "\\", ""
                    )
                    if rel != current_file:
                        results.append({
                            "file": rel,
                            "line": int(line_no) if line_no.isdigit() else 0,
                            "snippet": content.strip()[:120],
                        })
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        pass
    return results


def _extract_distinctive_token(snippet: str) -> str:
    """Extrae el substring más distintivo para cross-file grep."""
    # Preferir literales entre comillas
    match = re.search(r'"([^"]{4,80})"', snippet)
    if match:
        return match.group(1)
    match = re.search(r"'([^']{4,80})'", snippet)
    if match:
        return match.group(1)
    # Fallback: palabra más larga
    words = re.findall(r"[A-Za-z0-9_@.-]{4,}", snippet)
    if words:
        words.sort(key=len, reverse=True)
        return words[0][:80]
    return ""


def _extract_variable_names(snippet: str) -> list[str]:
    """Extrae nombres de variables + funciones del snippet."""
    # Patterns: variable = · const X = · private final X = · def func( · function X(
    names: set[str] = set()
    for pattern in [
        r"\b(?:const|var|let|public|private|static|final|protected)\s+(?:string|int|double|bool|long|float)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=",
        r"\bdef\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        r"\b([A-Za-z_][A-Za-z0-9_]{3,})\s*=\s*[\"']",
    ]:
        for m in re.finditer(pattern, snippet):
            if m.group(1) and m.group(1).lower() not in (
                "if", "for", "while", "return", "var", "let", "const",
                "function", "def", "public", "private", "static"
            ):
                names.add(m.group(1))
    return sorted(names)[:5]


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

_PROMPT_TEMPLATE = """Eres un security auditor senior revisando hallazgos de un escáner automatizado sobre el codebase de Aeroméxico (AMX) · sistema revenue accounting.

Un detector encontró este posible issue:
- Rule: {rule_id}
- Severity: {severity}
- CWE: {cwe}
- File: {file}:{line}
- Snippet: {snippet}

Contexto del código (±10 líneas):
```
{surrounding_code}
```

Git blame del line:
- Commit: {blame_commit}
- Author: {blame_author}
- Date: {blame_date}
- Message: "{blame_summary}"

Otras ocurrencias del mismo pattern en el workspace ({cross_count} files):
{cross_file_list}

Variables relevantes detectadas: {variable_names}

Behavior fingerprint (characterization · API pública del archivo):
{behavior_fingerprint}

Ontology hint (clasificación tentativa previa por catálogo AMX):
{ontology_hint}

Clasifica este finding en UNA de estas 4 categorías:

1. **bug** · vulnerabilidad clara de seguridad (CWE-798 credencial hardcoded · CWE-89 SQL injection · CWE-78 command injection · CWE-664 runtime exception como remove-in-iteration · CWE-362 race condition · etc). El auto-refactor es seguro aplicándolo.

2. **business_rule** · el valor es lógica de negocio intencional del dominio AMX (número de vuelo con acuerdo específico · SKU pinned por regulación · ID a sistema externo · threshold operativo). Auto-refactor rompería el dominio.

3. **migration_candidate** · pattern conocido con template de migración disponible (Secrets Manager · Route53 PHZ · KMS · Polly retry). Auto-fix aplicable con cuidado.

4. **unclear** · no hay suficiente contexto para determinar intent. Requiere review humano.

EJEMPLOS DE RAZONAMIENTO (pocos-shot):

Ejemplo A · credencial plaintext en App.config
- snippet: `<add key="password" value="ATOS5246" />`
- Razonamiento: "ATOS5246" es un literal string plaintext en config de producción, el key es "password" (no reference a SSM/KeyVault), no hay variable lookup. Esto es CWE-798 / CWE-522.
- JSON: {{"classification":"bug","confidence":0.95,"reasoning":"Credencial plaintext literal en config · CWE-522","evidence":["key='password'","valor literal","no reference Secrets Manager"],"recommended_action":"auto_fix"}}

Ejemplo B · flight number hardcoded
- snippet: `flight.flightNumber = "829";`
- git blame: "Ajuste manual para correr vuelo solicitado por ops · 2026-03"
- Razonamiento: git blame indica intervención manual ad-hoc para ejecución puntual, no es bug sino patch operativo. El número rota según request. Business rule temporal.
- JSON: {{"classification":"business_rule","confidence":0.75,"reasoning":"Patch operativo ad-hoc documentado en git blame · no literal de dominio estable","evidence":["git blame menciona 'ajuste manual'","ops operational context"],"recommended_action":"pause_for_review"}}

RAZONAMIENTO PASO A PASO (hazlo mentalmente, NO en la salida):
1. ¿Qué clase de CWE aplica realmente al snippet?
2. ¿El contexto del código y git blame sugieren intent malicioso, accidental, o deliberado de dominio?
3. ¿Hay behavior fingerprint que dé señal sobre rol del archivo?
4. ¿Ontology hint es consistente con mi análisis?
5. ¿Confidence final?

Responde SOLO con JSON válido (sin markdown fences · sin texto antes o después):
{{
  "classification": "bug|business_rule|migration_candidate|unclear",
  "confidence": 0.0-1.0,
  "reasoning": "1-2 oraciones explicando la decisión",
  "evidence": ["señal1", "señal2", "señal3"],
  "recommended_action": "auto_fix|pause_for_review|human_required"
}}

Criterios de confidence:
- 0.9-1.0 · evidence múltiple + variable name explícito + git context consistente
- 0.7-0.89 · mayoría de señales apuntan misma dirección
- 0.5-0.69 · señales mixtas · inclinado pero no seguro
- <0.5 · retorna classification=unclear · pause_for_review"""


def build_prompt(context: dict) -> str:
    """Construye el prompt para el LLM con el context gathered."""
    blame = context.get("git_blame") or {}
    cross = context.get("cross_file_occurrences") or []
    cross_list = "\n".join(
        f"  - {c['file']}:{c['line']} · {c['snippet']}" for c in cross
    ) if cross else "  (ninguna)"
    return _PROMPT_TEMPLATE.format(
        rule_id=context.get("rule_id", ""),
        severity=context.get("severity", ""),
        cwe=context.get("cwe", ""),
        file=context.get("file", ""),
        line=context.get("line", 0),
        snippet=context.get("snippet", "")[:200],
        surrounding_code=context.get("surrounding_code", "")[:2000],
        blame_commit=blame.get("commit", "(n/a)"),
        blame_author=blame.get("author", "(n/a)"),
        blame_date=blame.get("date", "(n/a)"),
        blame_summary=blame.get("summary", "(n/a)")[:200],
        cross_count=len(cross),
        cross_file_list=cross_list,
        variable_names=", ".join(context.get("variable_names", [])) or "(ninguna)",
        behavior_fingerprint=context.get("behavior_fingerprint", "") or "(sin fingerprint)",
        ontology_hint=context.get("ontology_hint", "") or "(sin hint previo)",
    )


# ---------------------------------------------------------------------------
# LLM Providers
# ---------------------------------------------------------------------------

class _BaseProvider:
    """Interface · cada provider implementa call(prompt) -> str."""
    def call(self, prompt: str, timeout: int = 30) -> str:
        raise NotImplementedError


class MockProvider(_BaseProvider):
    """Mock determinista · para tests · no llama API.

    Extrae el Snippet del finding desde el prompt (no el prompt entero)
    y clasifica por keywords del snippet:
    - 'password' · 'secret' · 'api_key' en snippet → bug
    - 'FlightNumber' o 'vuelo' + número específico → business_rule
    - 'ATOS' o 'legacy' → migration_candidate
    - resto → unclear

    Diseñado para que los unit tests NO dependan de API key y los devs
    puedan iterar sin costos. El real value del Nivel 2 viene con
    provider=anthropic|openai|ollama con API key válida.
    """
    def call(self, prompt: str, timeout: int = 30) -> str:
        # Extraer solo el snippet del finding (evitar falsos matches
        # por keywords del prompt template mismo)
        snippet_match = re.search(r"- Snippet:\s*(.+)", prompt)
        snippet = snippet_match.group(1).strip() if snippet_match else ""
        snippet_lower = snippet.lower()

        # Flight number hardcoded (business rule candidate · HIGH priority)
        if re.search(r'(?:flight|vuelo|flightnumber)', snippet_lower) and \
           re.search(r'[\'"]\d{2,4}[\'"]', snippet):
            return json.dumps({
                "classification": "business_rule",
                "confidence": 0.75,
                "reasoning": "Mock: flight number literal en contexto de FlightNumber · requiere confirmar con stakeholder si es regla de negocio",
                "evidence": ["flight number pattern", "domain-specific context"],
                "recommended_action": "pause_for_review",
            })
        # Legacy migration keywords
        if any(kw in snippet_lower for kw in ["atos5246", "legacy", "legacyacct"]):
            return json.dumps({
                "classification": "migration_candidate",
                "confidence": 0.72,
                "reasoning": "Mock: legacy keyword detectado · migracion conocida aplicable",
                "evidence": ["legacy keyword"],
                "recommended_action": "auto_fix",
            })
        # Credential keywords
        if any(kw in snippet_lower for kw in
               ["password", "secret", "api_key", "api key", "apikey",
                "@ssw0rd", "sk-live"]):
            return json.dumps({
                "classification": "bug",
                "confidence": 0.85,
                "reasoning": "Mock: snippet contiene keywords de credencial explicita",
                "evidence": ["credential keyword in snippet"],
                "recommended_action": "auto_fix",
            })
        return json.dumps({
            "classification": "unclear",
            "confidence": 0.40,
            "reasoning": "Mock: sin senales dominantes · requiere review humano",
            "evidence": [],
            "recommended_action": "pause_for_review",
        })


class AnthropicProvider(_BaseProvider):
    """Claude API · default para Nivel 2."""
    def __init__(self, api_key: str, model: str = "claude-opus-4-7"):
        self.api_key = api_key
        self.model = model

    def call(self, prompt: str, timeout: int = 30) -> str:
        try:
            import urllib.request
            import urllib.error
        except ImportError as exc:
            raise RuntimeError("urllib required for Anthropic provider") from exc

        body = json.dumps({
            "model": self.model,
            "max_tokens": 500,
            "messages": [{"role": "user", "content": prompt}],
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=body,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Anthropic API error: {exc}") from exc
        # Extract text from response
        content = data.get("content", [])
        for block in content:
            if block.get("type") == "text":
                return block.get("text", "")
        return ""


class OpenAIProvider(_BaseProvider):
    """OpenAI API · GPT-4 family."""
    def __init__(self, api_key: str, model: str = "gpt-4o"):
        self.api_key = api_key
        self.model = model

    def call(self, prompt: str, timeout: int = 30) -> str:
        import urllib.request
        import urllib.error
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
            "max_tokens": 500,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(f"OpenAI API error: {exc}") from exc
        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "")
        return ""


class OllamaProvider(_BaseProvider):
    """Ollama · local LLM · zero-cost · privacidad."""
    def __init__(self, model: str = "llama3.1", host: str = "http://localhost:11434"):
        self.model = model
        self.host = host

    def call(self, prompt: str, timeout: int = 60) -> str:
        import urllib.request
        import urllib.error
        body = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Ollama error: {exc}") from exc
        return data.get("response", "")


def _build_provider(provider_name: str, model: str, api_key_env: str,
                    host: str) -> _BaseProvider:
    """Factory · crea el provider según config."""
    name = (provider_name or "mock").lower()
    if name == "mock":
        return MockProvider()
    if name == "anthropic":
        key = os.environ.get(api_key_env or "ANTHROPIC_API_KEY", "")
        if not key:
            raise RuntimeError(
                f"Anthropic provider requires {api_key_env or 'ANTHROPIC_API_KEY'} env var"
            )
        return AnthropicProvider(key, model or "claude-opus-4-7")
    if name == "openai":
        key = os.environ.get(api_key_env or "OPENAI_API_KEY", "")
        if not key:
            raise RuntimeError(
                f"OpenAI provider requires {api_key_env or 'OPENAI_API_KEY'} env var"
            )
        return OpenAIProvider(key, model or "gpt-4o")
    if name == "ollama":
        return OllamaProvider(model or "llama3.1",
                              host or "http://localhost:11434")
    raise ValueError(f"Unknown provider: {name}")


# ---------------------------------------------------------------------------
# LLM Classifier (main class)
# ---------------------------------------------------------------------------

class LLMClassifier:
    """Clasifica findings usando LLM · con caché + budget cap.

    Config esperada:
    {
        "enabled": bool,                   # default False
        "provider": str,                   # mock|anthropic|openai|ollama
        "model": str,                      # ej. "claude-opus-4-7"
        "confidence_threshold": float,     # default 0.8
        "max_calls_per_scan": int,         # default 50 (budget cap)
        "api_key_env": str,                # ej. "ANTHROPIC_API_KEY"
        "timeout_seconds": int,            # default 30
        "cache_results": bool,             # default True
        "cache_path": str,                 # default ".aios-llm-cache.json"
        "ollama_host": str,                # default "http://localhost:11434"
    }
    """
    def __init__(
        self,
        provider: str = "mock",
        model: str = "",
        confidence_threshold: float = 0.8,
        max_calls_per_scan: int = 50,
        api_key_env: str = "",
        timeout_seconds: int = 30,
        cache_results: bool = True,
        cache_path: str = ".aios-llm-cache.json",
        ollama_host: str = "http://localhost:11434",
    ):
        self.provider_name = provider
        self.model = model
        self.confidence_threshold = confidence_threshold
        self.max_calls_per_scan = max_calls_per_scan
        self.api_key_env = api_key_env
        self.timeout_seconds = timeout_seconds
        self.cache_results = cache_results
        self.cache_path = cache_path
        self.ollama_host = ollama_host
        self._provider: Optional[_BaseProvider] = None
        self._calls_made = 0
        self._cache: dict[str, dict] = {}

    @classmethod
    def from_config(cls, cfg: dict) -> "LLMClassifier":
        cfg = cfg or {}
        return cls(
            provider=cfg.get("provider", "mock"),
            model=cfg.get("model", ""),
            confidence_threshold=float(cfg.get("confidence_threshold", 0.8)),
            max_calls_per_scan=int(cfg.get("max_calls_per_scan", 50)),
            api_key_env=cfg.get("api_key_env", ""),
            timeout_seconds=int(cfg.get("timeout_seconds", 30)),
            cache_results=bool(cfg.get("cache_results", True)),
            cache_path=cfg.get("cache_path", ".aios-llm-cache.json"),
            ollama_host=cfg.get("ollama_host", "http://localhost:11434"),
        )

    def _ensure_provider(self) -> _BaseProvider:
        if self._provider is None:
            self._provider = _build_provider(
                self.provider_name, self.model,
                self.api_key_env, self.ollama_host,
            )
        return self._provider

    def _cache_key(self, context: dict) -> str:
        """Key estable · hash de los campos que matter."""
        commit = (context.get("git_blame") or {}).get("commit", "")
        material = (
            f"{context.get('file','')}:"
            f"{context.get('line',0)}:"
            f"{context.get('rule_id','')}:"
            f"{commit}"
        )
        return hashlib.sha1(material.encode("utf-8")).hexdigest()[:16]

    def _load_cache(self, root: Path) -> None:
        if not self.cache_results:
            return
        cache_file = root / self.cache_path
        if cache_file.exists():
            try:
                self._cache = json.loads(cache_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._cache = {}

    def _save_cache(self, root: Path) -> None:
        if not self.cache_results:
            return
        try:
            cache_file = root / self.cache_path
            cache_file.write_text(
                json.dumps(self._cache, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError:
            pass

    def classify(self, finding: object, root: Path) -> LLMClassificationResult:
        """Clasifica un finding · usa caché si existe · respeta budget."""
        # Load cache on first call
        if self.cache_results and not self._cache:
            self._load_cache(root)

        context = gather_context(finding, root)
        cache_key = self._cache_key(context)

        # Check cache
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            return LLMClassificationResult(
                classification=cached.get("classification", "unclear"),
                confidence=float(cached.get("confidence", 0.0)),
                reasoning=cached.get("reasoning", ""),
                evidence=cached.get("evidence", []) or [],
                recommended_action=cached.get("recommended_action", "pause_for_review"),
                provider=self.provider_name,
                model=self.model,
                cached=True,
            )

        # Budget check
        if self._calls_made >= self.max_calls_per_scan:
            return LLMClassificationResult(
                classification="unclear",
                confidence=0.0,
                reasoning=f"Budget exhausted (max {self.max_calls_per_scan} calls)",
                recommended_action="pause_for_review",
                provider="(budget-exhausted)",
            )

        # Call LLM
        try:
            prompt = build_prompt(context)
            provider = self._ensure_provider()
            raw = provider.call(prompt, timeout=self.timeout_seconds)
            self._calls_made += 1
            result = self._parse_response(raw)
            result.provider = self.provider_name
            result.model = self.model
        except Exception as exc:  # noqa: BLE001 · fallos de LLM no deben romper scan
            return LLMClassificationResult(
                classification="unclear",
                confidence=0.0,
                reasoning=f"LLM call failed: {exc}",
                recommended_action="pause_for_review",
                provider=self.provider_name,
            )

        # Save to cache
        if self.cache_results:
            self._cache[cache_key] = {
                "classification": result.classification,
                "confidence": result.confidence,
                "reasoning": result.reasoning,
                "evidence": result.evidence,
                "recommended_action": result.recommended_action,
            }
            self._save_cache(root)

        return result

    def _parse_response(self, raw: str) -> LLMClassificationResult:
        """Parsea el JSON response del LLM · con fallbacks."""
        if not raw:
            return LLMClassificationResult(
                classification="unclear",
                confidence=0.0,
                reasoning="Empty LLM response",
                recommended_action="pause_for_review",
            )
        text = raw.strip()
        # Strip markdown fences si el LLM las incluyó
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
        # Primer objeto JSON plausible
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            text = match.group(0)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return LLMClassificationResult(
                classification="unclear",
                confidence=0.0,
                reasoning=f"Invalid JSON from LLM: {raw[:100]}",
                recommended_action="pause_for_review",
            )
        cls = data.get("classification", "unclear")
        if cls not in VALID_CLASSIFICATIONS:
            cls = "unclear"
        action = data.get("recommended_action", "pause_for_review")
        if action not in VALID_ACTIONS:
            action = "pause_for_review"
        try:
            confidence = float(data.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))
        evidence = data.get("evidence", []) or []
        if not isinstance(evidence, list):
            evidence = [str(evidence)]
        return LLMClassificationResult(
            classification=cls,
            confidence=confidence,
            reasoning=str(data.get("reasoning", ""))[:500],
            evidence=[str(e)[:100] for e in evidence[:10]],
            recommended_action=action,
        )

    @property
    def calls_made(self) -> int:
        return self._calls_made

    @property
    def budget_remaining(self) -> int:
        return max(0, self.max_calls_per_scan - self._calls_made)
