# AIOS — AI Engineering Operating System

Spec-driven development framework with agent orchestration, modeled after Kiro-style workflows.

**Versión actual: v3.8.2** (2026-04-29 · Governance Pack · 5 subcomandos `aios governance` + `aios tier classify`)

## Install (primera vez)

```bash
git clone https://github.com/christianescamilla15-cell/aios-framework.git
cd aios-framework
python3 -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e .
aios version                  # debe imprimir v3.8.2
```

## Update a la última versión (desde clone existente)

```bash
cd aios-framework
git fetch --all --tags
git checkout main
git pull origin main          # trae merges + tags hasta v3.7.5
source .venv/bin/activate
pip install -e . --upgrade    # re-instala paquete editable con dependencias actualizadas
aios version                  # confirma versión actualizada (>= v3.8.2)
```

Si quieres pinear a un tag específico:

```bash
git checkout v3.8.2           # detached HEAD en tag · safe para CI/CD pinning
pip install -e .
```

## Quick Start

```bash
# Initialize in any project
aios init

# Create a task (auto-detects mode)
aios task --task "Add analytics dashboard"

# Start session
aios boot

# Check status
aios status

# Analyze repo
aios analyze

# Check release readiness
aios release

# End session
aios refresh --summary "Built dashboard" --next-step "Add tests"
```

## Governance Pack (v3.8.0+)

5 subcomandos para automatizar el flujo de gobernanza AMX (Revenue Accounting):

```bash
# Validar reglas (TIER · naming · approvals · stakeholders) sobre un app
aios governance check --app sicofav --root .

# Generar PDF formal de solicitud (5 templates: bd-access · aws-account · cmk · yubikey · dl-inclusion)
aios governance request --type bd-access --app sicofav --output ./requests/

# Audit trail SHA256 chain · 11 estados · tampering-evident
aios governance audit --app sicofav --update --signer "Luis Ertuche" --status in-review

# Escalación slippage automática (auto-routing severity → destinatario)
aios governance escalate --app sicofav --auto

# Clasificación TIER por 9 criterios oficiales AMX
aios tier classify --app srg --explain
```

Ver guía completa en [docs/GOVERNANCE_GUIDE.md](docs/GOVERNANCE_GUIDE.md).

## Generación de documentación · Discovery + Compliance + Phase1

> Comandos para producir entregables Fase 1 (plan v5) + reportes regulatorios. Output esperado: 9 docs Discovery + 1 PDF maestro + reportes LFPDPPP/PCI/SOX.

### 1 · Discovery 9 docs (Fase 1 plan v5)

Genera los 9 entregables estándar en `<root>/analisis/fase-1-discovery/`:

```bash
# Generación básica · 9 markdown docs
aios discovery-generate --app sicofav --root /ruta/al/refactor

# Con PDFs (requiere weasyprint · v3.7.1+)
pip install weasyprint
aios discovery-generate --app sicofav --root /ruta/al/refactor --pdf

# Sobreescribir docs existentes (default skip-existing preserva work humano)
aios discovery-generate --app sicofav --root /ruta/al/refactor --overwrite
```

Apps soportadas: `sicofav`, `arc`, `bsp`, `asr`, `srg`, `cfdis`, `robot`, `noshow`, `com-d`, `com-i` (10 del plan v5).

**Outputs**:

```
analisis/fase-1-discovery/
├── 01_code_scan.md          · output formateado de aios scan
├── 02_hallazgos_mapped.md   · findings mapeados a CWE + regulaciones
├── 03_arq_as_is.md          · stack + topología AS-IS
├── 04_stakeholders.md       · owners funcional + técnico + governance
├── 05_vulns.md              · vulns detalle + compliance LFPDPPP/PCI/SOX/CFF
├── 06_deps.md               · dependencias + upgrade targets
├── 07_preguntas_nuevas.md   · template bloqueadoras + categorizadas
├── 08_bloqueadores.md       · cross-app + específicos del app
├── 09_risk_register.md      · riesgos probabilidad × impacto por tier
└── pdfs/                    · v3.7.1+ con --pdf
```

### 2 · Phase 1 Report consolidado (master document para PM)

Combina los 9 docs Discovery en un master markdown para presentar a stakeholders:

```bash
aios phase1-report --app sicofav --root /ruta/al/refactor

# Con PDF master adicional
aios phase1-report --app sicofav --root /ruta/al/refactor --pdf
```

Output: `<root>/PHASE1_REPORT_<app>.md` (+ `.pdf` opcional).

### 3 · Compliance Report (LFPDPPP · PCI-DSS · SOX · CFF · OWASP)

Genera reporte de compliance · findings agrupados por marco regulatorio:

```bash
# MD output a CWD
aios compliance-report --root /ruta/al/refactor --format md --output reports/compliance.md

# HTML (interactive)
aios compliance-report --root /ruta/al/refactor --format html --output reports/compliance.html

# PDF (firma stakeholder)
aios compliance-report --root /ruta/al/refactor --format pdf --output reports/compliance.pdf

# Stdout (CI integration)
aios compliance-report --root /ruta/al/refactor --format md
```

**v3.7.5+** · `--output` resuelve relativo a CWD (no `--root`). Si pasas `--output reports/x.md` desde tu repo · escribe en `<repo>/reports/x.md` · NO en `<root>/reports/x.md`.

**v3.7.4+** · suppressions de `aios-suppressions.json` se aplican igual que en `aios release` y `aios iterate`.

### 4 · Iterate scan (multi-strategy · regex + ensemble + LLM)

Para findings exhaustivos antes de generar Discovery:

```bash
# Regex-only (rápido · default zero-cost)
aios iterate --root /ruta/al/refactor --max-iterations 1 --strategies regex

# Multi-strategy (regex + ensemble · más cobertura)
aios iterate --root /ruta/al/refactor --max-iterations 3 --strategies regex,ensemble

# Con LLM deep-review (requiere OLLAMA o ANTHROPIC_API_KEY)
aios iterate --root /ruta/al/refactor --max-iterations 3 \
    --strategies regex,ensemble,llm_deep_review \
    --llm-provider anthropic --llm-model claude-sonnet-4-6

# JSON output para automation
aios iterate --root /ruta/al/refactor --format json > findings.json
```

**v3.7.5+** · `_safe_finditer()` con timeout 2s default por regex · cierra hangs sobre archivos YAML grandes (k8s manifests · etc.). Override:

```bash
AIOS_REGEX_TIMEOUT_SECONDS=5 aios iterate --root /ruta/al/refactor
```

### 5 · Suppressions (waivers documentados)

Para gestionar false positives sin fork del framework:

```bash
# Listar findings activos
aios review list

# Aprobar finding como suppression con justificación
aios review approve --id FRK-a3f8e1b2 --reason "intentional · IMDS denylist anti-SSRF"

# Generar review docs (markdown templates) para findings pause
aios review generate
```

Estructura `aios-suppressions.json` (en repo root):

```json
{
  "version": "1.1",
  "suppressions": [
    {
      "id": "T3-FP-001",
      "rule": "CWE-547",
      "file": "src/x.cs",
      "line_range": "144-148",
      "justification": "T-06 IMDS denylist intencional · denylist ES la mitigación SSRF",
      "reviewed_by": "Christian Hernandez",
      "reviewed_date": "2026-04-27",
      "expires": "2027-04-27"
    }
  ]
}
```

**v3.7.4+** · `compliance-report` + `iterate` consumen suppressions (antes solo `release`).
**v3.7.5+** · path normalization · suppression con repo-root path matchea finding scope-reducido.

## Commands

| Command | Description |
|---------|-------------|
| `aios init` | Initialize AIOS in a project |
| `aios task` | Create task with auto mode detection |
| `aios boot` | Load context and start session |
| `aios refresh` | Save session state |
| `aios status` | Show project status |
| `aios analyze` | Analyze repo + run stack checks |
| `aios iterate` | Multi-strategy security scan (regex · ensemble · LLM) |
| `aios discovery-generate` | Auto-genera 9 docs Discovery Fase 1 plan v5 |
| `aios phase1-report` | Master markdown consolidando 9 docs Discovery |
| `aios compliance-report` | Mapeo findings a LFPDPPP / PCI-DSS / SOX / CFF / OWASP |
| `aios release` | Check release readiness · aplica suppressions |
| `aios review` | Approve / reject / defer findings · genera review docs |
| `aios doctor` | Diagnose AIOS health |
| `aios handoff` | Generate handoff document |
| `aios module` | List/check stack modules |
| `aios config` | Project configuration |
| `aios version` | Show version |

## Modes

- **BUGFIX** — surgical fixes, regression tests
- **FEATURE** — incremental implementation
- **MIGRATION** — phased cloud migration
- **LEGACY_MODERNIZATION** — stabilize and modernize

## Stacks

multiagent, python, react, cicd, aws, docker, dotnet — auto-detected per project.

## Detectores AMX-specific (29 totales)

Subset clave (BO-AMX governance):

- `AMX-CDK-STACK-REQUIRES-MANDATORY-TAGS` · 8 tags AMX canonical (CentroDeCosto · DuenoDeLaCuenta · Proyecto · Ambiente · ImpactoANegocio · Aplicacion · GrupoDeParcheo · SistemaOperativo)
- `AMX-KMS-AWS-MANAGED-PROHIBITED` · CMK customer-managed obligatorio
- `AMX-S3-MISSING-KMS-ENCRYPTION` · S3 buckets sin KMS CMK
- `AMX-SERVICE-PROHIBITED` · ECS / SES / SNS prohibidos por arquitectura T0
- `AUTH-MISSING-NET-CONTROLLER` · controllers .NET sin `[Authorize]` (v3.7.4 respeta class-level + inline)
- `STATIC-GENERIC-EXCEPTION-CATCH-CSHARP` · catch-all sloppy (v3.7.4 degrade con `when` filter)
- `HARDCODED-INTERNAL-HOSTNAME` · hostnames internos hardcoded
- `STATIC-CMD-SHELL-TRUE` · `subprocess.run(shell=True)` Python
- `STATIC-SQL-FSTRING` · SQL injection via f-string

Lista completa: `aios analyze --root <repo>` muestra todos los detectores activos.

## Tests

```bash
# Test suite completo
python3 -m pytest

# Subset · scan tests
python3 -m pytest tests/test_security_gate.py -v

# Suppressions
python3 -m pytest tests/test_suppressions.py -v
```

Estado v3.7.5: **428 tests pass** · 0 fail.

## Versions changelog (resumen)

| Versión | Fecha | Highlight |
|---|---|---|
| v3.7.5 | 2026-04-27 | 3 framework gaps cross-app: path normalization · regex timeout · compliance-report --output CWD |
| v3.7.4 | 2026-04-27 | 5 detector quality gaps: class-level Authorize · catch when filter · suppressions iterate · CWE alias |
| v3.7.3 | 2026-04-24 | AMX-SERVICE-PROHIBITED detector (ECS/SES/SNS) |
| v3.7.2 | 2026-04-24 | AMX KMS customer-managed detector |
| v3.7.1 | 2026-04-24 | Discovery PDF generation (weasyprint) |
| v3.7.0 | 2026-04-23 | Discovery 9 docs auto-generator |

Detalle completo: `BACKLOG.md` + `git log --oneline --tags`.
