---
description: "Break down a feature or fix into implementation tasks with agent assignments"
triggers:
  - "break down tasks"
  - "implementation plan"
  - "task list"
  - "create tasks"
---

# Task Breakdown

Break work into discrete, executable tasks.

## Task Format

For each task:
```
### T{number}: {title}
- Description: what needs to be done
- Owner Agent: Architect / Developer / Test / Security / Reviewer / Deployment
- Dependencies: T{n} (which tasks must complete first)
- Deliverables: files created or modified
- Validation: how to verify it's done correctly
- Risk: low / medium / high
```

## Agent Roles
- **Architect**: architecture decisions, boundaries, patterns
- **Developer**: code generation, refactors, adapters
- **Test**: unit tests, integration tests, regression
- **Security**: secrets handling, IAM, vulnerability review
- **Reviewer**: code review, standards compliance
- **Deployment**: Docker, CI/CD, infra, rollout

## Rules
- Tasks should be independently executable where possible
- Critical path tasks first
- Include validation for every task
- Reference the design doc for architecture context
- After creating tasks, run `aios release` to check readiness
