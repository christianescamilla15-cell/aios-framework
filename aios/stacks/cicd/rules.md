# CI/CD Stack Rules

## Pipeline
- Every repo MUST have a CI pipeline (GitHub Actions, GitLab CI, etc.)
- Pipeline MUST run on every push to main/master
- Pipeline MUST include: lint, test, build
- Pipeline SHOULD include: security scan, deploy

## Git
- Descriptive commit messages (what + why)
- Never force push to main/master
- Branch protection on main
- PRs require at least 1 review (or CI pass)

## Deployment
- Staging before production
- Rollback plan documented for every deploy
- Health check after deploy
- Canary or phased rollout for critical services

## Rollback
- Every deployment must be reversible
- Rollback steps documented in spec
- Database migrations must be backward compatible
- Feature flags for risky changes

## Secrets
- Never commit secrets
- Use environment variables or secret managers
- Rotate keys after exposure
- .env in .gitignore always

## Monitoring
- Logs accessible post-deploy
- Error alerting configured
- Response time tracking
- Uptime monitoring for production services
