# .NET Stack Rules

## Conventions
- Migrate `.NET Framework 4.x` (EOL ene-2026) to `.NET 8 LTS` minimum
- Use `[Authorize(Roles=...)]` for authorization (no OnClick without auth check)
- `customErrors mode="On"` in production (CWE-209)
- `compilation debug="false"` in production (CWE-489)
- AWS Secrets Manager / Vault for credentials (NO hardcoded in web.config)

## Testing
- xUnit or NUnit · target ≥40% coverage minimum
- Test naming: `ClassNameTests.cs`
- Mock external dependencies (Moq · NSubstitute)

## Architecture
- Clean Architecture layered (API · Application · Domain · Infrastructure)
- Dependency Injection (`Microsoft.Extensions.DependencyInjection`)
- Repository pattern for data access
- Adapter pattern for external systems

## Resilience
- Polly library for retry + circuit breaker
- Exponential backoff for external calls
- Timeout explícito en HTTP/SOAP calls
- IDisposable: always use `using` statements

## Logging
- Serilog structured JSON
- CloudWatch sink in AWS environments
- CorrelationId per request
- NO `Console.WriteLine` in production

## Security
- AWS Secrets Manager for credentials
- KMS-encrypted at rest
- TLS 1.3 for external integrations
- No HTTP plain (use HTTPS)
- `[Authorize]` attribute on endpoints
- Validate user input (path traversal · CWE-22)

## CI/CD
- GitHub Actions or Azure DevOps
- 4 mandatory pre-prod scans (AMX policy): Tenable · Veracode · WIZ · Prisma
- Blue-green deployment via AWS CodeDeploy
- Branch protection on main

## Migration legacy → modern
- `.NET Upgrade Assistant` for 4.x → 8 migration
- Migrate VB.NET → C# where critical
- Replace System.Web → ASP.NET Core
- Replace ConfigurationManager → IConfiguration
- Migrate stored procedures → EF Core LINQ where simple

## Anti-patterns to fix
- `catch (Exception)` generic → use specific exception types
- `Console.WriteLine` → Serilog
- Hardcoded IPs/connection strings → appsettings.json + Secrets Manager
- Hardcoded business values (e.g. flight numbers) → config or DB
- Missing `using` for IDisposable → always wrap in using
- Stored procedures with CURSOR → set-based queries
