# Java Stack Rules

## Conventions
- JDK 17 LTS minimum · prefer JDK 21 LTS for new code
- Spring Boot 3.x (Spring Framework 6)
- Maven preferred · Gradle acceptable
- Java naming: `PascalCase` classes · `camelCase` methods/vars

## Testing
- JUnit 5 (Jupiter) · Mockito for mocking
- Target ≥40% coverage minimum
- Test naming: `ClassNameTest.java` in `/src/test/java/`
- Integration tests separated (`@SpringBootTest`)

## Architecture
- Spring Boot Auto-configuration
- DI via `@Autowired` (constructor injection preferred)
- Repository pattern (Spring Data JPA / JDBC)
- Service layer for business logic
- Controllers thin (validation + delegation)

## Resilience
- Resilience4j library for retry · circuit breaker · bulkhead
- Spring Retry as alternative
- Timeouts explicit en RestTemplate/WebClient
- Try-with-resources for AutoCloseable

## Logging
- SLF4J + Logback (Spring Boot default)
- JSON structured logs in production
- CorrelationId via MDC
- NO `System.out.println` in production

## Security
- Spring Security
- Secrets via Vault / AWS Secrets Manager / env vars
- NO hardcoded credentials
- TLS for external integrations
- Input validation (Jakarta Validation `@Valid`)

## CI/CD
- GitHub Actions / Jenkins / GitLab CI
- Maven/Gradle build
- 4 mandatory pre-prod scans (ACME policy): Tenable · Veracode · WIZ · Prisma
- Container Docker (NO ECS · constraint ACME)
- Spring Actuator for health/metrics

## Spring Boot best practices
- `@RestController` over `@Controller`
- `application.yml` preferred over `.properties`
- Profile-aware config (`@Profile("dev")`)
- Externalize secrets (NEVER in `application.yml` directly)
- Spring Cloud Config for centralized config

## Anti-patterns to fix
- `catch (Exception)` generic → specific exceptions
- `System.out.println` → SLF4J logger
- Field injection (`@Autowired` field) → constructor injection
- Hardcoded URLs/IPs → `application.yml` properties
- Missing `@Transactional` boundaries
- `String + concatenation` → StringBuilder for loops
