# AIOS — AI Engineering Operating System

Spec-driven development framework with agent orchestration, modeled after Kiro-style workflows.

## Install

```bash
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

## Commands

| Command | Description |
|---------|-------------|
| `aios init` | Initialize AIOS in a project |
| `aios task` | Create task with auto mode detection |
| `aios boot` | Load context and start session |
| `aios refresh` | Save session state |
| `aios status` | Show project status |
| `aios analyze` | Analyze repo + run stack checks |
| `aios release` | Check release readiness |
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

multiagent, python, react, cicd, aws, docker — auto-detected per project.
