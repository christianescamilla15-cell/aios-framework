# PHP Stack Rules

## Conventions
- PHP 8.x minimum (8.3 LTS preferred)
- Composer mandatory for dependencies
- Laravel 10+ or Symfony 6+ for new projects
- Plain PHP legacy: migrate to framework progressively
- PSR-12 coding style

## Testing
- PHPUnit 10+
- Target ≥40% coverage
- Tests in `/tests/` directory
- Mock external services

## Architecture
- MVC pattern (framework-driven)
- Repository pattern for DB
- Service layer for business logic
- Dependency injection (Laravel container · Symfony DI)

## Resilience
- Guzzle for HTTP with retry middleware
- Try-catch typed exceptions
- Database transactions explicit

## Logging
- Monolog (PSR-3 compliant)
- JSON structured logs
- NO `error_log` ad-hoc
- NO `var_dump` / `print_r` in production

## Security (CRITICAL · PHP common attack surface)
- **NEVER** trust `$_GET`, `$_POST`, `$_REQUEST` directly
- Use prepared statements (PDO with `?` placeholders)
- Escape output: `htmlspecialchars($var, ENT_QUOTES, 'UTF-8')`
- CSRF tokens (Laravel/Symfony built-in)
- NEVER `eval`, `shell_exec`, `system` without validation
- File uploads: validate extension + MIME + scan
- Sessions: secure cookies + HTTPOnly + SameSite
- Password hashing: `password_hash($pwd, PASSWORD_BCRYPT)`

## CI/CD
- GitHub Actions / GitLab CI
- Composer install + tests
- 4 mandatory pre-prod scans (AMX policy)
- Container Docker (NO ECS · constraint AMX)

## Framework best practices

### Laravel
- Use Eloquent ORM (avoid raw SQL)
- Migrations for schema changes
- Queues for async (Redis/SQS)
- API resources for serialization
- `php artisan` commands for CLI tasks

### Symfony
- Use Doctrine ORM
- DI container · services explicit
- Symfony Console for CLI
- Twig for templates

### Plain PHP legacy (avoid · migrate)
- Move to framework progressively
- Extract DB logic to PDO + prepared statements
- Add Composer for autoloading
- Add PHPUnit incrementally

## Anti-patterns to fix
- `mysqli_query($sql . $_GET[...])` → prepared statement
- `echo $_POST['x']` → `htmlspecialchars`
- `shell_exec` con input usuario → reemplazar con library
- `eval()` → reemplazar lógica
- `extract($_GET)` → variable injection · NUNCA
- `include $_GET['file']` → file inclusion · NUNCA
- Sin Composer → migrar
- `error_log` ad-hoc → Monolog
