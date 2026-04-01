# Architecture Context

## Agent-Based Systems Built

### MultiAgente (Resident Support)
- 8 agents: Router, Sentinel, Nova, Atlas, Aria, Orion, Nexus, Closure
- Orchestrator pipeline: identify → classify → verify → route → respond → log
- PostgreSQL: 11 tables, 500 residents, 3000 payments, 200 tickets
- Admin Panel: 8 sections (dashboard, residents, tickets, payments, sessions, sync, audit, runs)

### NexusForge (Agent Orchestration Platform)
- 22 agents across 3 use cases
- DAG execution engine with parallel step groups
- 3-tier memory (working, episodic, semantic)
- Multi-LLM router with circuit breaker
- WebSocket real-time streaming
- 15 database migrations

### VoiceScribe (Transcription)
- 4 modes: PC mic, WhatsApp, phone calls, Zoom
- Groq Whisper for transcription
- WebSocket sync between devices
- WhatsApp file processing (PDF, Word, images)

## Common Patterns
- Orchestrator pattern: central coordinator delegates to specialized agents
- Circuit breaker: automatic failover between LLM providers
- Audit trail: every action logged for traceability
- Graceful degradation: system works even when services are unavailable
- Auto-migration: database schema updates on startup

## Fragile Areas
- Groq free tier: 100K tokens/day limit
- Render free tier: 30s cold start, sleeps after 15 min
- Twilio sandbox: expires every 72h
