# Enterprise Policy

## Spec
- Spec REQUIRED for all tasks
- Design doc REQUIRED for features and migrations
- Risk assessment REQUIRED before implementation
- Rollback plan REQUIRED for any production change

## Release
- All tests MUST pass
- No open critical risks
- Rollback plan verified
- Handoff document for team changes
- Security review for sensitive modules

## Code
- Type hints required (>80% coverage)
- No print() in production code
- Health endpoints mandatory
- Audit logging for state changes
- No hardcoded secrets (enforced)

## Migration
- Phased rollout required
- Backward compatibility mandatory
- Parallel run before cutover
- Monitoring in place before deploy
