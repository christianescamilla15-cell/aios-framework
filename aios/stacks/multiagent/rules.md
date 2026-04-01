# Multiagent Stack Rules

## Agent Design
- Every agent MUST have a single responsibility
- Agents MUST NOT call other agents directly — use orchestrator
- Every agent MUST return structured output (not free text)
- Every agent MUST have a demo/fallback mode
- Agent prompts MUST be max 300 tokens (force brevity)

## Orchestration
- Use a central orchestrator pattern (not peer-to-peer)
- Intent classification MUST happen before agent routing
- Low confidence (<0.4) routes to general/fallback agent
- Sensitive operations MUST require verification gate

## LLM Integration
- ALWAYS use environment variables for API keys
- ALWAYS implement provider fallback (primary + secondary)
- ALWAYS handle rate limits gracefully (fallback to keyword classifier)
- ALWAYS track tokens and cost per request
- NEVER hardcode API keys

## Verification
- Sensitive data (billing, personal info) requires OTP or auth
- Session expiration: max 30 minutes
- Max 3 OTP attempts before lockout
- Audit log every verification event

## Observability
- Log every agent execution (run_id, agent, intent, latency, tokens)
- Track agent path (which agents handled the request)
- Log errors with full context
- Dashboard must show real metrics, not demo data

## Testing
- Test each agent independently with known inputs
- Test routing for all intent categories
- Test verification flow (send, verify, reject, lockout)
- Test rate limit fallback behavior
- Test edge cases (unknown user, empty message, long message)

## Database
- Auto-migrate on startup
- Seed data for demos (realistic, not lorem ipsum)
- Audit trail for all state changes
- Soft delete (never hard delete user data)
