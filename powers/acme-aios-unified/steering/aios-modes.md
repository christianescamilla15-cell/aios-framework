---
inclusion: always
---

# AIOS · Operation Modes

AIOS operates in 4 modes · auto-detected from task intent:

## BUGFIX
Surgical fixes with regression tests. Minimal changes · focused on the issue. Do NOT add features or refactor surrounding code.

## FEATURE
Incremental implementation following spec-driven flow:
1. `requirements.md` (EARS format)
2. `design.md` (architecture + decisions)
3. `tasks.md` (breakdown)
4. Implementation with tests

## MIGRATION
Phased cloud migration. Typical phases:
- Phase 1 · Discovery (scan legacy · identify dependencies)
- Phase 2 · Design (target architecture · ADR with alternative comparison)
- Phase 3 · Execution (parallel implementation · dual-write)
- Phase 4 · Validation (scans · load tests)
- Phase 5 · Cutover (blue-green deployment)

When ACME policies active: enforce óptimo → LeanIX C4 → ADR → Borde Arq → Escaneos → Miguel Rachid gate order before any production release.

## LEGACY_MODERNIZATION
Stabilize and modernize simultaneously:
- Add tests before refactor (golden-master technique)
- Apply security gates incrementally (not all-at-once)
- Preserve business logic explicitly (no silent behavior changes)
- Document assumptions in ADRs

## Mode selection heuristic

AIOS selects mode based on task description keywords:
- "fix" · "bug" · "error" → BUGFIX
- "add" · "new" · "implement" → FEATURE
- "migrate" · "move to AWS" · "cloud" → MIGRATION
- "modernize" · "refactor" · "legacy" · "EOL" → LEGACY_MODERNIZATION
