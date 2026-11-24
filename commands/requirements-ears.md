---
description: "Generate requirements in EARS format (Easy Approach to Requirements Syntax)"
triggers:
  - "requirements"
  - "acceptance criteria"
  - "user stories"
  - "EARS"
  - "write requirements"
---

# Requirements Engineering (EARS Format)

Generate structured requirements using the EARS notation standard.

## EARS Patterns

### 1. Ubiquitous (always true)
```
The system SHALL [action].
```
Example: The system SHALL encrypt all data at rest using AES-256.

### 2. Event-Driven (when something happens)
```
WHEN [event], the system SHALL [action].
```
Example: WHEN a user submits a login form, the system SHALL validate credentials within 200ms.

### 3. State-Driven (while in a state)
```
WHILE [state], the system SHALL [action].
```
Example: WHILE the user session is active, the system SHALL refresh the auth token every 15 minutes.

### 4. Unwanted Behavior (handling failures)
```
IF [unwanted condition], THEN the system SHALL [action].
```
Example: IF the database connection fails, THEN the system SHALL retry 3 times with exponential backoff.

### 5. Optional (conditional features)
```
WHERE [feature/condition], the system SHALL [action].
```
Example: WHERE multi-factor authentication is enabled, the system SHALL require OTP verification.

## Output Format
Create requirements.md with:
1. Numbered requirements using EARS patterns
2. Non-functional requirements (performance, security, reliability)
3. Acceptance criteria as checkboxes
4. Out of scope items

## Rules
- Each requirement must be testable
- Use SHALL for mandatory, SHOULD for recommended
- One requirement per statement
- Reference existing files with #[[file:path]] when relevant
