---
displayName: ACME AIOS Unified v3.3
description: Pack ACME unificado v3.3.1 · spec-driven dev + security gate (85 detectores · 28 CWEs) + cross-copy drift + PII runtime scan + ensemble OSS + LLM classifier RAG · compliant retro 20-abr
keywords:
  - acmeair
  - acme
  - aios
  - spec-driven
  - security
  - mythos
  - arena
  - nemesis
  - am-kiro
  - sast
  - drift
  - pii-scan
---

# ACME AIOS Unified Power · v3.3.1

Pack unificado que expone **AIOS · Mythos · Arena · Nemesis** como un solo Power de Kiro. Cubre el ciclo completo de desarrollo moderno ACME · ahora con **4 detectores únicos vs SAST comercial** (drift · credential byte-identity · third-party exfil · runtime PII) + LLM classifier Nivel 2 con RAG.

- **AIOS** (spec-driven + session management): router + spec generator + execution engine + context refresh
- **Mythos** (security scanning): **85 detectores · 28 CWEs (100% únicos)** · 9 lenguajes
- **Arena** (self-play validation): runner de adversarial testing contra TUTs
- **Nemesis** (engagement scaffolding): catálogo 10 apps ACME · scaffold por quarter

Cumple retro 20-abr: sin ECS · sin SES · sin SNS · KMS + Akamai + observabilidad correlation-id.

## Modos soportados

- `BUGFIX` · fix localizado + regression test
- `FEATURE` · nueva capability end-to-end (requirements EARS → design → tasks)
- `MIGRATION` · cambio de stack con paridad funcional
- `LEGACY_MODERNIZATION` · refactor profundo con gates ACME

**Nota UI (BUG-001):** Kiro expone sólo `Build a Feature` / `Fix a Bug` aunque este pack declare 4. Workaround: describe intent explícitamente ("LEGACY_MODERNIZATION · refactor de …") y el router interno resuelve correctamente.

## MCP Tools expuestos (via `aios-mcp` · 8 tools instrumentados kcb)

| Tool | Framework | Uso |
|---|---|---|
| `security_scan(project_path)` | Mythos | Corre scanner embebido · retorna findings + severity · v3.3.1 detecta PII logs · host key · SMTP TLS · substring identity · `.Hours` misuse · IP literals |
| `release_gate_check(project_path)` | AIOS | Release gate completo · 10 checks ACME (incluye behavior preservation · SITL queue · domain ontology) |
| `arena_list_targets()` | Arena | Lista TUTs disponibles |
| `arena_run(target, max_rounds, target_url?)` | Arena | Corre self-play contra un TUT |
| `engagement_list()` | Nemesis | Lista catálogo 10 apps ACME |
| `engagement_scaffold(app_id, quarter?)` | Nemesis | Genera scaffold del engagement |
| `aggregate_report(project_path)` | AIOS | Consolida reporte markdown de la sesión |
| `forbidden_literals_suggest()` | AIOS | Sugiere literales prohibidos (policy ACME) |

## CLI capabilities nuevas (v2.2 → v3.3 · no-MCP · invocables vía Bash)

| Comando | Versión | Función |
|---|:---:|---|
| `aios drift --source A --compare B` | v2.2.0 | Detecta framework/endpoint/cert drift + credenciales byte-idénticas cross-env (único vs SAST comercial) |
| `aios exfil --root . --corporate <domains>` | v2.4.0 | Emails/URLs/hosts a dominios no-corporativos · env_hint automático |
| `aios runtime-data --root .` | v2.4.0 | PII scan de HTML/TXT/LOG/CSV · 10 detectores (PNR · PAN · JWT · CURP · etc) |
| `aios ensemble --root . --tools semgrep,bandit,...` | v2.6.0 | Wrapper de 6 OSS tools · normaliza findings |
| `aios iterate --root . --strategies regex,ensemble,llm,taint` | v3.2.0 | Multi-strategy saturation loop · para en convergencia |
| `aios dynamic-hooks --root .` | v2.8.0 | Genera xUnit/pytest stubs + reglas Falco + sugerencias OTel |
| `aios classify --file X --line N --rule-id R --provider ollama\|anthropic` | v1.9.0+ | LLM Nivel 2 con RAG + CoT (ver §LLM más abajo) |
| `aios characterize --capture/--verify` | v2.0.0 | API fingerprint para detectar breaking changes pre/post refactor |
| `aios review <list/show/approve/reject/defer> --id FRK-xxx` | v2.1.0 | Stakeholder-in-the-Loop · audit trail `.aios/review-log.jsonl` |
| `aios resume` + `aios checkpoint` | v1.7.4 | Workstream persistence cross-session |

## LLM Classifier Nivel 2 (RFC-003 · v2.7.0+)

Proveedores soportados:
- **`ollama`** (default · zero-cost · local · modelos: llama3.1 · gemma3 · devstral · qwen3)
- **`anthropic`** (vía `ANTHROPIC_API_KEY` · modelos claude-opus-4-7 · claude-sonnet-4-6 · claude-haiku-4-5)
- **`openai`** (GPT-4o · GPT-4o-mini)
- **`mock`** (testing)

Config en `aios-config.json`:
```json
{
  "security_gate": {
    "llm_classifier": {
      "enabled": true,
      "provider": "ollama",
      "model": "gemma3:latest",
      "confidence_threshold": 0.7,
      "timeout_seconds": 180,
      "cache_enabled": true
    }
  }
}
```

v2.7.0 prompt upgrades: chain-of-thought · few-shot examples · RAG context (characterization fingerprint + ontology hint).

## Cómo el agente Kiro usa este Power

El Power expone **steering rules** (carpeta `steering/`) que el agente sigue automáticamente, y **MCP tools** que el agente invoca cuando el flujo lo requiere.

- **Antes de cada tarea** (`02_session_boot.md`): el agente puede invocar `forbidden_literals_suggest` para cargar policy
- **Después de cambios significativos** (`04_execution.md`): invocar `security_scan` antes de commit
- **Antes de merge/release** (`acme-constraints-retro-20abr.md`): invocar `release_gate_check`
- **Al cerrar sesión** (`05_context_refresh.md`): invocar `aggregate_report` para persistir estado
- **Validación cross-copy** (pre-deploy): correr `aios drift --source source-tree --compare build-output` desde Bash
- **Validación PII en logs productivos**: `aios runtime-data --root logs/` desde Bash pre-upload

## Requisitos

- **Python 3.12+** con `aios-framework >= 3.3.0` instalado:
  ```bash
  pip install -e /path/to/aios-framework
  # o vía tag:
  pip install git+https://github.com/christianescamilla15-cell/aios-framework.git@v3.3.1
  ```
- Verificar que `aios-mcp` esté en PATH: `which aios-mcp`
- **Opcional**: Ollama (`curl -fsSL https://ollama.com/install.sh | sh`) + `ollama pull gemma3` para LLM classifier local
- **Opcional**: `pip install semgrep bandit checkov` para ensemble OSS
- **Opcional**: `ANTHROPIC_API_KEY` env var para Opus/Sonnet en classify

## Coverage · capabilities medidas honestamente

- **Security detectors:** 85 (+18% vs v1.7.1)
- **CWE coverage:** 28/28 (100% únicos vs 21/28 · 75% antes)
- **Stacks soportados:** AWS · CI/CD · COBOL · Docker · .NET · Java · Multiagent · PHP · Python
- **Policies:** `default` · `enterprise` · `acme-finance_operations` (26 patterns con multi-match v3.1)

### Coverage medido vs auditor humano senior (validado por 2 clean sessions Opus)

Sobre **ATOS-NOSHOW-ROBOT** (.NET 4.7.2 legacy · 1.5 KLoC · 24 archivos .cs):

| Métrica | Valor | Fuente |
|---|---|---|
| Full coverage (sólo ✓) | **39%** (11/28) | 2nd clean session |
| Incl. parciales (✓+~) | **53%** (15/28) | 2nd clean session |
| Técnico excl. governance | **65%** (15/23) | 2nd clean session |
| Irreductible (compliance · meta · deploy drift) | **18%** | Rice's theorem + governance |

**Bonus · el framework encuentra bugs que el humano NO listó**: DR-25 (.Hours vs .TotalHours revenue silencioso) · DR-18 (substring name matching ticket mis-attribution). Ambos ahora scanner-directo en v3.3.1.

### Benchmarks industria (estado-del-arte)

- SAST comercial publicado: 11-46% recall (EASE 2024 · 4 tools individuales)
- CodeQL F1 OWASP Benchmark: 74.4% (Konvu 2026 · con 68% FPR)
- IRIS (CodeQL+GPT-4): 27-46% por CWE (arXiv 2405.17238)
- **AIOS v3.3.1: 53-65% sobre código real con 18% irreductible documentado**

Narrativa defendible: 2-3x mejor que SAST comercial sobre código real · SIN prometer el 99.99% que la literatura no permite (Rice's theorem).

## Steering incluido (10 archivos)

- `00_master_rules.md` · meta-reglas del agente
- `01_router.md` · router de modos
- `02_session_boot.md` · boot de sesión
- `03_spec_generator.md` · generador de specs EARS
- `04_execution.md` · ejecución paso a paso
- `05_context_refresh.md` · refresh contextual
- `aios-overview.md` · overview del framework
- `aios-stacks-auto-detection.md` · detección automática de stack
- `aios-modes.md` · detalle de los 4 modos
- `acme-constraints-retro-20abr.md` · constraints ACME post retro 20-abr

## Audit Bridge · integración con kcb (kiro-claude-bridge)

Los 8 tools están instrumentados para emitir eventos `mcp_tool_call` (start/end con `correlation_id` + `duration_ms`) al `kcb bridge`. Esto permite auditar end-to-end cada invocación MCP hecha por Kiro — factorizaciones, scans, release gates.

**Cómo activarlo**: edita el `mcp.json` instalado (`~/.kiro/powers/installed/acme-aios-unified/mcp.json`) e inyecta las env vars:

```json
{
  "mcpServers": {
    "aios": {
      "command": "aios-mcp",
      "args": [],
      "env": {
        "KCB_SESSION_ID": "<session id from: kcb start>",
        "KCB_STATE_DIR": "<absolute path a .kcb-state/>",
        "KCB_ACTOR": "aios-mcp"
      }
    }
  }
}
```

Después: `Ctrl+Shift+P` → `Developer: Reload Window` en Kiro para que el MCP subprocess reinicie con el env actualizado.

**Qué se emite por cada tool call**:
- Event `start` con `tool` name + `args` sanitizados (truncados a 200 chars)
- Event `end` con `duration_ms` + `error` si la excepción subió
- Mismo `correlation_id` une ambos para tracking

**Safety**: si `KCB_SESSION_ID` no está set, el decorator es no-op · la instrumentación nunca rompe el tool (exceptions swallowed).

## Changelog v1.7.1 → v3.3.1

- **v2.2.0** · RFC-004a + 004b · Cross-Copy Drift + Credential Byte-Identity (únicos vs SAST comercial)
- **v2.4.0** · RFC-004c + 004d · Third-Party Exfil + Runtime PII scanner
- **v2.5.0** · 5 detectores Cat B (remove-in-iter · singleton · generic-catch · ToList · missing-retry)
- **v2.6.0** · Ensemble OSS wrapper (semgrep · bandit · gitleaks · trufflehog · checkov · trivy)
- **v2.7.0** · LLM classifier upgrade · RAG + chain-of-thought + few-shot
- **v2.8.0** · Dynamic hooks (xUnit/pytest stubs · Falco rules · OTel spans)
- **v3.0.0** · EVIDENCE_BUNDLE consolidado · 8-layer pipeline
- **v3.1.0** · 5 fixes + 6 detectores (PII log · sensitive log · host key · SMTP TLS · stack exposure · throw-ex)
- **v3.2.0** · Iterative multi-strategy saturation scanner
- **v3.3.1** · 3 detectores revenue-críticos (`.Hours` misuse · IP literal · substring name matching)

## Origen y autoría

- **Autor:** Christian Hernández Escamilla · eTride
- **Repo fuente:** `github.com/christianescamilla15-cell/aios-framework` (rama `feat/am-kiro-compat` · tag `v3.3.1`)
- **Compatible con:** AM-KIRO framework ACME (`github.com/OYN-ACME/am-kiro` · sesión Ciber 20-abr)
- **Versión:** 3.3.1
