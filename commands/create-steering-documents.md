---
description: "Generate project steering documents for consistent AI interactions"
triggers:
  - "steering documents"
  - "project standards"
  - "setup guidelines"
  - "create steering"
  - "configure project"
---

# Create Steering Documents

Generate steering files that give persistent context to AI interactions.

## What to Create

### 1. project-standards.md (always included)
- Coding conventions
- Naming patterns
- File organization rules
- Documentation requirements

### 2. Language-specific (fileMatch)
For Python projects:
```yaml
---
inclusion: fileMatch
fileMatchPattern: "*.py"
---
```
- Type hints required
- async/await for I/O
- pytest for testing

For React projects:
```yaml
---
inclusion: fileMatch
fileMatchPattern: "*.jsx"
---
```
- Functional components only
- Custom hooks for shared logic

### 3. git-workflow.md (always)
- Branch naming
- Commit message format
- PR process

### 4. Security guide (manual)
```yaml
---
inclusion: manual
---
```
- Only loaded when explicitly requested
- Security policies, access control rules

## Quick Setup
Run `aios onboard` to auto-generate steering from repo analysis.

## File References
Use `#[[file:path/to/spec.yaml]]` to include external specs or configs as context.
