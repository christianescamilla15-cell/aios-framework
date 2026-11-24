---
inclusion: always
---

# AIOS · AI Engineering Operating System

AIOS is a spec-driven development framework with agent orchestration · modeled after Kiro-style workflows · extended with embedded security detectors and governance-as-code.

## Core capabilities

- **Session management:** `aios boot` loads context · `aios refresh` saves state
- **Spec-driven:** EARS requirements · design documents · task breakdown
- **Security scanning:** embedded regex detectors mapped to CWE (`aios analyze --security`)
- **Stack auto-detection:** aws · cicd · cobol · docker · dotnet · java · multiagent · php · python · react
- **Release gate:** specs + tests + security gate + optional external scanners (Semgrep · Trivy · Checkov)
- **Governance:** TIER classification · naming conventions · approval chain with SHA-256 audit trail
- **Operation modes:** BUGFIX · FEATURE · MIGRATION · LEGACY_MODERNIZATION

## Integration with Kiro

1. Steering rules in `.kiro/steering/` are loaded by the Kiro agent
2. The MCP server (`aios.mcp_server`) exposes the scanner and the release gate to the agent
3. `aios sync` regenerates `.kiro/steering/` from `ai-system/`

## Organization policy

Organization-specific rules (approved services, naming, tiers, approvers) live in data, never in code:
`aios/governance/rules/*.yaml` and the `ORG-*` detectors. The repository ships a fictitious example
organization (Acme Corp); replace those files with your own.
