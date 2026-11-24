---
displayName: AIOS Unified
description: Spec-driven development + security gate (detectores por regex con CWE) + drift entre copias + PII en datos de ejecución + clasificador LLM opcional, expuestos al agente de Kiro por MCP.
keywords:
  - aios
  - spec-driven
  - security
  - sast
  - drift
  - pii-scan
  - governance
---

# AIOS Unified Power

Power de Kiro que expone **AIOS** al agente: el flujo spec-driven (router, generador de specs EARS,
ejecución, refresco de contexto) más el security gate y las herramientas de análisis.

## Modos soportados

- `BUGFIX` · fix localizado + prueba de regresión
- `FEATURE` · capacidad nueva de punta a punta (requirements EARS → design → tasks)
- `MIGRATION` · cambio de stack con paridad funcional
- `LEGACY_MODERNIZATION` · refactor profundo con compuertas de seguridad

Kiro sólo muestra `Build a Feature` / `Fix a Bug` en su interfaz: para los otros dos modos describe la
intención de forma explícita («LEGACY_MODERNIZATION · refactor de …») y el router interno lo resuelve.

## Herramientas MCP (`aios-mcp`)

| Tool | Uso |
|---|---|
| `security_scan(project_path)` | Corre el escáner embebido y devuelve hallazgos con severidad y CWE |
| `release_gate_check(project_path)` | Release gate completo (specs, pruebas, security gate, ontología de dominio) |
| `arena_list_targets()` / `arena_run(...)` | Self-play adversarial contra objetivos de prueba (requiere el CLI `arena`) |
| `engagement_list()` / `engagement_scaffold(...)` | Andamiaje de engagements de red team (requiere el scaffolder externo) |
| `aggregate_report(project_path)` | Reporte markdown consolidado de la sesión |
| `forbidden_literals_suggest(project_path)` | Guía para configurar literales prohibidos sin exponerlos |

## Comandos de la CLI útiles desde el agente

| Comando | Función |
|---|---|
| `aios drift --source A --compare B` | Diferencias de framework/endpoint/certificado y credenciales byte-idénticas entre copias |
| `aios exfil --root . --corporate <dominios>` | Correos/URLs/hosts hacia dominios no corporativos |
| `aios runtime-data --root .` | PII en HTML/TXT/LOG/CSV (PAN con Luhn, JWT, CURP, RFC, localizadores) |
| `aios ensemble --root .` | Envoltura de herramientas OSS (semgrep, bandit, gitleaks, trufflehog, checkov, trivy) |
| `aios iterate --root .` | Escaneo multi-estrategia hasta convergencia |
| `aios classify --file X --line N --rule-id R` | Clasificador LLM (bug · regla de negocio · migración · dudoso) |
| `aios characterize --capture/--verify` | Huella de la API pública para detectar cambios incompatibles |
| `aios review ...` | Revisión humana con bitácora `.aios/review-log.jsonl` |
| `aios governance ...` / `aios tier classify` | Gobierno como código (TIER, nombres, cadena de firmas) |

## Cómo lo usa el agente

- **Antes de cada tarea** (`02_session_boot.md`): carga contexto y la política de literales
- **Después de cambios significativos** (`04_execution.md`): `security_scan` antes del commit
- **Antes de merge/release**: `release_gate_check`
- **Al cerrar sesión** (`05_context_refresh.md`): `aggregate_report`

## Auditoría de llamadas (opcional)

Las herramientas MCP emiten eventos `mcp_tool_call` (inicio/fin con `correlation_id` y `duration_ms`)
si el entorno define `KCB_SESSION_ID`, `KCB_STATE_DIR` y `KCB_ACTOR` en `mcp.json`. Sin esas variables el
decorador no hace nada y nunca rompe la herramienta.

## Requisitos

- Python 3.12 con el paquete instalado: `pip install -e /ruta/a/aios-framework`
- `aios-mcp` en el PATH (`which aios-mcp`)
- Opcional: Ollama o `ANTHROPIC_API_KEY` para el clasificador LLM; `semgrep`, `bandit`, `checkov` para `aios ensemble`

## Steering incluido

`00_master_rules.md` · `01_router.md` · `02_session_boot.md` · `03_spec_generator.md` · `04_execution.md` ·
`05_context_refresh.md` · `aios-overview.md` · `aios-stacks-auto-detection.md` · `aios-modes.md`
