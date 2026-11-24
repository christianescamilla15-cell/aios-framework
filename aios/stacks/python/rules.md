# Python Stack Rules

## Project Structure
- Use `app/` for application code
- Use `tests/` for test files
- Use `requirements.txt` or `pyproject.toml` for dependencies
- Use `.env` for secrets (never commit)
- Include `.env.example` with placeholder values

## Code Style
- Type hints on all function signatures
- Pydantic v2 for data validation
- async/await for I/O operations
- Structured logging (not print statements in production)
- Max function length: ~50 lines

## FastAPI Conventions
- Prefix routes with `/api/`
- Use Pydantic models for request/response
- Lifespan for startup/shutdown (not events)
- CORS configured for known origins
- Health check endpoint at `/api/health` or `/health`

## Database
- Use asyncpg for PostgreSQL (not SQLAlchemy unless required)
- Auto-migrate on startup
- Use parameterized queries ($1, $2) — never string interpolation
- Connection pooling (min 2, max 10)

## Testing
- pytest as test runner
- Test files: `test_*.py` or `*_test.py`
- Minimum: test each endpoint, test each service function
- Use fixtures for DB setup/teardown

## Security
- Environment variables for all secrets
- Input validation on all endpoints
- Rate limiting on public endpoints
- No SQL injection (parameterized queries only)
