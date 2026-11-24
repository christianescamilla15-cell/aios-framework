# AIOS — AI Engineering Operating System

This project is the AIOS framework, a Kiro-compatible spec-driven development system.

## Available Commands (run in terminal)
- `aios init` — initialize AIOS in any project
- `aios onboard` — auto-setup wizard for enterprise repos
- `aios task --task "description"` — create spec with auto mode detection
- `aios boot` — start session, load context
- `aios status` — show project status
- `aios analyze` — repo analysis + stack checks
- `aios diff` — incremental changes
- `aios impact` — dependency graph
- `aios release` — release gate validation
- `aios guide` — troubleshooting FAQ (8 topics)
- `aios hook install --name pre-commit` — install git hooks
- `aios mcp init` — generate Kiro MCP config
- `aios refresh --summary "..." --next-step "..."` — save session

## Skills (in /commands/)
- spec-driven-development — full 3-phase workflow
- requirements-ears — EARS format requirements
- design-documentation — technical architecture
- task-breakdown — implementation planning
- troubleshooting — debug methodology
- create-steering-documents — project guidelines
- release-validation — pre-deploy checklist

## Workflow
1. `aios onboard` (first time)
2. `aios task --task "..."` (creates spec)
3. Work through specs (requirements → design → tasks)
4. `aios release` (validate)
5. `aios refresh` (save context)

## Install
```bash
pip install aios-kiro
```
