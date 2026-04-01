# Docker Stack Rules

## Dockerfile
- Use specific base image tags (not :latest)
- Multi-stage builds for smaller images
- Non-root user in production
- .dockerignore to exclude unnecessary files
- COPY requirements first, then code (layer caching)

## Docker Compose
- Use for local development
- Define all services (app, db, redis, etc.)
- Use volumes for data persistence
- Environment variables via .env file
- Health checks on services

## Security
- No secrets in Dockerfile or compose
- Use build args for build-time only
- Scan images for vulnerabilities
- Pin base image versions

## Best Practices
- One process per container
- Log to stdout/stderr
- Graceful shutdown handling
- Resource limits defined
