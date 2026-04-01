---
description: "Complete spec-driven development workflow: requirements (EARS) → design → tasks → implementation"
triggers:
  - "create a spec"
  - "plan this feature"
  - "spec-driven"
  - "new feature spec"
  - "design this"
---

# Spec-Driven Development

You are operating in AIOS spec-driven mode. Follow this strict workflow:

## Phase 1: Requirements (EARS Format)
Create requirements using the EARS syntax:
- **Ubiquitous**: The system SHALL [action]
- **Event-Driven**: WHEN [event], the system SHALL [action]
- **State-Driven**: WHILE [state], the system SHALL [action]
- **Unwanted**: IF [condition], THEN the system SHALL [action]
- **Optional**: WHERE [feature], the system SHALL [action]

Include: user impact, acceptance criteria, out of scope.

## Phase 2: Design
Create a design document covering:
- Current state analysis
- Proposed architecture
- Data flow / API impact
- Tradeoffs and rejected alternatives
- Risks

## Phase 3: Tasks
Break work into discrete tasks:
- Each task has: description, owner agent, dependencies, validation criteria, risk level
- Tasks should be executable independently where possible
- Include validation step for each task

## Rules
- Do NOT code before completing Phase 1 and 2
- Always read /ai-memory/ for project context before starting
- Use #[[file:path]] to reference relevant existing files
- Create all spec files under /specs/{mode}-{slug}/
- After completing specs, run: `aios release` to validate readiness
