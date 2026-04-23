---
inclusion: always
---

# AIOS · AI Engineering Operating System

AIOS is a spec-driven development framework with agent orchestration · modeled after Kiro-style workflows · extended with 72 security detectors and AMX governance compliance.

## Core capabilities exposed when this pack is installed

- **Session management:** `aios boot` loads context · `aios refresh` saves state
- **Spec-driven:** EARS requirements · design documents · task breakdown
- **Security scanning:** 72 detectors across 21/28 CWEs (75% audit v4)
- **Stack auto-detection:** aws · cicd · cobol · docker · dotnet · java · multiagent · php · python
- **Release gate:** integrates WIZ · Veracode · Prisma · Tenable scan results
- **Operation modes:** BUGFIX · FEATURE · MIGRATION · LEGACY_MODERNIZATION

## Integration with AM-KIRO

When this pack is installed via `am-kiro install aios`:
1. Steering rules in `.kiro/steering/` are loaded by Kiro IDE Agent
2. Hooks in `.kiro/hooks/` run at pre-task and post-session
3. MCP server (`aios.mcp_server`) becomes available to the Kiro Agent
4. Settings in `.kiro/settings/` merge with existing project config

## AMX-specific behavior

When the workspace detects AMX policies (`policies/amx-revenue-accounting/`) · AIOS enforces:
- ECS service prohibition (must use EKS or Serverless)
- SES + SNS prohibition (must use Relay interno AMX)
- KMS 1 per service (no shared CMKs)
- Akamai mandatory at edge for internet-facing apps
- Role naming prefix `amx-r-*` (enforced by SCPs)
- Scan sequence before production: WIZ → Veracode → Prisma → Tenable
