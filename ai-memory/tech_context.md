# Tech Context

## Primary Stack
- Frontend: React 18 + Vite 5
- Backend: FastAPI (Python 3.12), Node.js/Express
- Database: PostgreSQL (asyncpg), pgvector, Supabase
- LLM: Groq (Llama 3.3 70B), Claude API, Whisper
- Mobile: Flutter (Dart), Kotlin
- Deployment: Vercel (frontend), Render (backend), Docker

## Infrastructure
- Cloud: AWS (Terraform, ECS, RDS, S3), Render, Vercel
- CI/CD: GitHub Actions
- Containers: Docker, docker-compose
- IaC: Terraform
- Monitoring: Sentry, custom observability (agent_runs table)

## Testing
- Python: pytest
- JavaScript: Vitest + Testing Library
- 861+ tests across all projects

## API Integrations
- Twilio (WhatsApp OTP)
- Resend (email)
- Google Drive, Notion, Gmail
- Groq API, Claude API, OpenAI

## Security
- OTP verification for sensitive data
- Audit logging (resident_change_log)
- Environment variables only (NEVER hardcode keys)
- Session expiration (30 min TTL)

## Key Patterns
- Multi-LLM routing with circuit breaker
- DAG-based workflow execution
- Agent orchestration pipeline
- Strangler pattern for migrations
