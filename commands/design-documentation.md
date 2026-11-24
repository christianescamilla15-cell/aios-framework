---
description: "Create technical design documentation for a feature or migration"
triggers:
  - "design document"
  - "architecture"
  - "technical design"
  - "design this system"
---

# Design Documentation

Create a comprehensive design document.

## Structure

### 1. Current State
- What exists today
- Architecture overview
- Known limitations

### 2. Proposed Design
- Target architecture
- Components and interactions
- Data flow
- API changes

### 3. Key Decisions
- Decision + rationale
- Alternatives considered and why rejected
- Tradeoffs accepted

### 4. Impact Analysis
- Which modules are affected
- Database changes
- API compatibility
- Performance implications

### 5. Risks
- Technical risks
- Migration risks
- Rollback strategy

## Rules
- Read /ai-memory/architecture_context.md first
- Reference existing code with #[[file:path]]
- Run `aios impact --file changed_file.py` to find affected modules
- Keep the design actionable, not theoretical
