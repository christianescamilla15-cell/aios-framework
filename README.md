# AIOS (Dowser) — AI Engineering Operating System

Spec-driven development framework with agent orchestration, modeled after Kiro-style workflows, plus an
embedded security gate (regex detectors mapped to CWE), governance-as-code and a VS Code extension.

**Versión actual: v4.0.0** — primera versión pública. Las reglas de organización (TIER, nombres, firmas,
servicios aprobados) son **datos de ejemplo de una organización ficticia, Acme Corp** (ver el encabezado
de `aios/governance/rules/*.yaml`).

## Install

```bash
git clone https://github.com/christianescamilla15-cell/aios-framework.git
cd aios-framework
python3 -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[mcp]"      # [mcp] agrega el servidor MCP (aios-mcp)
aios version
```

## Quick Start

```bash
aios init                                         # inicializa AIOS en un proyecto
aios task --task "Add analytics dashboard"        # crea la spec (detecta el modo)
aios boot                                         # carga contexto
aios analyze                                      # análisis del repo + checks por stack
aios release                                      # compuerta de release (specs, pruebas, seguridad)
aios refresh --summary "Built dashboard" --next-step "Add tests"
```

## Security gate

`aios analyze --security` y `aios release` corren los detectores embebidos (Python, C#, VB.NET, Java,
PHP, JS/TS, COBOL, configuración .NET, CDK/Terraform y buildspec). Cada hallazgo lleva su CWE.

| Familia | Ejemplos de reglas |
|---|---|
| Código | `STATIC-SQL-FSTRING`, `STATIC-CMD-SHELL-TRUE`, `HARDCODED-INTERNAL-HOSTNAME`, `AUTH-MISSING-NET-CONTROLLER` |
| .NET | `DOTNET-HARDCODED-DECRYPT-KEY`, `DOTNET-PREDICTABLE-SALT`, `DOTNET-TRUST-SERVER-CERTIFICATE`, `ASPNET-IDENTITY-WEAK-PASSWORD` |
| AWS / CDK | `AWS-KMS-AWS-MANAGED-PROHIBITED`, `AWS-S3-MISSING-KMS-ENCRYPTION`, `AWS-CDK-SG-OPEN-INGRESS`, `AWS-CDK-FSTRING-WITH-TOKEN` |
| Política de organización (ejemplo) | `ORG-SERVICE-PROHIBITED`, `ORG-IAM-ROLE-WRONG-PREFIX`, `ORG-CDK-STACK-REQUIRES-MANDATORY-TAGS`, `ORG-CICD-BUILDSPEC-MISSING-TZ` |

Herramientas complementarias: `aios drift` (diferencias y credenciales byte-idénticas entre copias por
ambiente), `aios exfil` (correos/URLs hacia dominios no corporativos), `aios runtime-data` (PII en logs,
CSV y plantillas), `aios iterate` (regex + herramientas OSS + LLM opcional hasta convergencia),
`aios classify` (clasificador LLM: bug · regla de negocio · migración · dudoso) y `aios review`
(revisión humana con bitácora). Las supresiones viven en `aios-suppressions.json` con fecha de vencimiento.

## Governance-as-code

```bash
aios tier classify --app partners --explain        # 9 criterios + incoherencias del TIER declarado
aios governance check --app billing --root .       # TIER + nombres + estado de firmas
aios governance request --type bd-access --app billing --format md
aios governance escalate --app billing --auto      # escalamiento por días sin avance
```

Guía: [docs/GOVERNANCE_GUIDE.md](docs/GOVERNANCE_GUIDE.md).

## Discovery de modernización

```bash
aios discovery-generate --app billing --root ~/apps/billing   # 9 entregables de la fase 1
aios phase1-report --app billing --root ~/apps/billing        # paquete consolidado
aios compliance-report --root . --format md                   # hallazgos por LFPDPPP / PCI-DSS / SOX / OWASP
aios org-analog --root .                                      # repos análogos del catálogo de la organización
```

Guía: [docs/DISCOVERY_GUIDE.md](docs/DISCOVERY_GUIDE.md).

## Modes

- **BUGFIX** — surgical fixes, regression tests
- **FEATURE** — incremental implementation
- **MIGRATION** — phased cloud migration
- **LEGACY_MODERNIZATION** — stabilize and modernize

## Stacks

aws, cicd, cobol, docker, dotnet, java, multiagent, php, python, react — auto-detected per project.

## Integraciones

- **Kiro**: `.kiro/steering/` y el power `powers/aios-unified/` (steering + `mcp.json`).
- **MCP**: `aios-mcp` expone el escáner, el release gate y el reporte consolidado.
- **VS Code**: [vscode-extension/](vscode-extension/) envuelve la CLI (comandos, barra de estado, snippets).
