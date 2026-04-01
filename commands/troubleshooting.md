---
description: "Troubleshoot issues, debug problems, resolve common errors"
triggers:
  - "debug"
  - "troubleshoot"
  - "issue with"
  - "not working"
  - "error"
  - "fix this"
---

# Troubleshooting

When debugging, follow this systematic approach:

## Step 1: Isolate
- What changed recently? Run `aios diff`
- What modules are affected? Run `aios impact --file <changed_file>`
- Is this a known issue? Run `aios guide --topic troubleshooting`

## Step 2: Analyze
- Check the error message carefully
- Look at recent git commits
- Check if the issue is in a hotspot file (run `aios analyze`)

## Step 3: Fix
- Create a BUGFIX spec: `aios task --task "Fix: description" --mode BUGFIX`
- Surgical fix only — don't refactor unrelated code
- Add regression test before or after the fix

## Step 4: Validate
- Run `aios release` to check readiness
- Verify no regressions
- Update ai-memory/known_risks.md if relevant

## Common Problems
- Rate limit: add fallback/retry logic
- Import errors: check dependencies and virtual env
- Test failures: run only affected tests first
- Merge conflicts: check `aios diff` for scope of changes
- Lost context: run `aios boot` to reload project memory
