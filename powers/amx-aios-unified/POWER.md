---
displayName: AMX AIOS Unified
description: Pack AMX unificado · spec-driven dev + security gate (72 detectores · 21/28 CWEs) + self-play (Arena) + engagement scaffold (Nemesis) · compliant con retro 20-abr
keywords:
  - aeromexico
  - amx
  - aios
  - spec-driven
  - security
  - mythos
  - arena
  - nemesis
  - am-kiro
---

# AMX AIOS Unified Power

Pack unificado que expone **AIOS · Mythos · Arena · Nemesis** como un solo Power de Kiro. Cubre el ciclo completo de desarrollo moderno AMX:

- **AIOS** (spec-driven + session management): router + spec generator + execution engine + context refresh
- **Mythos** (security scanning): 72 detectores · 21/28 CWEs (75%) · 9 lenguajes
- **Arena** (self-play validation): runner de adversarial testing contra TUTs
- **Nemesis** (engagement scaffolding): catálogo 10 apps AMX · scaffold por quarter

Cumple retro 20-abr: sin ECS · sin SES · sin SNS · KMS + Akamai + observabilidad correlation-id.

## Modos soportados

- `BUGFIX` · fix localizado + regression test
- `FEATURE` · nueva capability end-to-end (requirements EARS → design → tasks)
- `MIGRATION` · cambio de stack con paridad funcional
- `LEGACY_MODERNIZATION` · refactor profundo con gates AMX

**Nota UI (BUG-001):** Kiro expone sólo `Build a Feature` / `Fix a Bug` aunque este pack declare 4. Workaround: describe intent explícitamente ("LEGACY_MODERNIZATION · refactor de …") y el router interno resuelve correctamente.

## MCP Tools expuestos (via `aios-mcp`)

| Tool | Framework | Uso |
|---|---|---|
| `security_scan(project_path)` | Mythos | Corre scanner embebido · retorna findings + severity |
| `release_gate_check(project_path)` | AIOS | Release gate completo · 7 checks AMX |
| `arena_list_targets()` | Arena | Lista TUTs disponibles |
| `arena_run(target, max_rounds, target_url?)` | Arena | Corre self-play contra un TUT |
| `engagement_list()` | Nemesis | Lista catálogo 10 apps AMX |
| `engagement_scaffold(app_id, quarter?)` | Nemesis | Genera scaffold del engagement |
| `aggregate_report(project_path)` | AIOS | Consolida reporte markdown de la sesión |
| `forbidden_literals_suggest()` | AIOS | Sugiere literales prohibidos (policy AMX) |

## Cómo el agente Kiro usa este Power

El Power expone **steering rules** (carpeta `steering/`) que el agente sigue automáticamente, y **MCP tools** que el agente invoca cuando el flujo lo requiere. Dado que Kiro Powers no soporta hooks automáticos, las reglas del steering indican **cuándo** llamar cada tool:

- **Antes de cada tarea** (`02_session_boot.md`): el agente puede invocar `forbidden_literals_suggest` para cargar policy
- **Después de cambios significativos** (`04_execution.md`): invocar `security_scan` antes de commit
- **Antes de merge/release** (`amx-constraints-retro-20abr.md`): invocar `release_gate_check`
- **Al cerrar sesión** (`05_context_refresh.md`): invocar `aggregate_report` para persistir estado

## Requisitos

- **Python 3.12+** con `aios-framework` instalado:
  ```bash
  pip install -e /path/to/aios-framework
  # o
  pip install aios-framework  # cuando se publique
  ```
- Verificar que `aios-mcp` esté en PATH: `which aios-mcp`

## Coverage / Capabilities

- **Security detectors:** 72
- **CWE coverage:** 21/28 (75%)
- **Stacks soportados:** AWS · CI/CD · COBOL · Docker · .NET · Java · Multiagent · PHP · Python
- **Policies:** `default` · `enterprise` · `amx-revenue-accounting`
- **Sprint:** 5.3 · validado end-to-end con NoShow (1507 líneas · 109 tasks · 10 BLOCKERS gates AMX)

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
- `amx-constraints-retro-20abr.md` · constraints AMX post retro 20-abr

## Origen y autoría

- **Autor:** Christian Hernández · eTrive
- **Repo fuente:** `github.com/eTrive/aios-framework` (rama `feat/am-kiro-compat`)
- **Compatible con:** AM-KIRO framework AMX (`github.com/OYN-AMX/am-kiro` · sesión Ciber 20-abr)
- **Versión:** 1.7.1
