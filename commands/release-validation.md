---
description: "Validate release readiness with gates, checks, and rollback planning"
triggers:
  - "release"
  - "ready to deploy"
  - "can we ship"
  - "pre-release check"
  - "deploy checklist"
---

# Release Validation

Before shipping, validate all gates.

## Automated Checks
Run `aios release` to verify:
- [ ] Active spec exists with all required files
- [ ] Tasks are defined
- [ ] Validation criteria documented
- [ ] Risks documented
- [ ] Rollback plan defined (for migrations/features)

## Manual Checks
- [ ] Design reviewed by team
- [ ] Tests pass locally
- [ ] No hardcoded secrets (run `aios module check --stack multiagent`)
- [ ] Health endpoint works
- [ ] Staging tested

## Stack-Specific
Run `aios analyze` to see stack checks:
- Python: type hints, health endpoint, no print()
- React: no hardcoded keys, build passes
- Docker: no :latest, no secrets in Dockerfile
- CI/CD: pipeline exists, .env in .gitignore

## Rollout
After validation:
1. Merge to main
2. Deploy to staging
3. Smoke test
4. Deploy to production
5. Monitor for 30 min
6. Run `aios refresh` to update memory
