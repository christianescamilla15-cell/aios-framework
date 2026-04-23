---
inclusion: fileMatch
fileMatchPattern: ['pyproject.toml', 'package.json', 'pom.xml', 'csproj', 'Gemfile', 'Cargo.toml', 'go.mod']
---

# AIOS · Stack Auto-Detection

When a project is opened with AIOS (via `aios init` or AM-KIRO install) · the framework detects installed stacks by scanning for marker files:

| Stack | Marker files |
|---|---|
| Python | `pyproject.toml` · `requirements.txt` · `setup.py` |
| .NET | `*.csproj` · `*.sln` · `Directory.Build.props` |
| Java | `pom.xml` · `build.gradle` |
| PHP | `composer.json` · `composer.lock` |
| COBOL | `*.cbl` · `*.cob` · `copybooks/` |
| Docker | `Dockerfile` · `docker-compose.yml` |
| AWS | `template.yaml` · `cdk.json` · `serverless.yml` |
| CI/CD | `.github/workflows/` · `.gitlab-ci.yml` · `Jenkinsfile` |
| Multi-agent | `.agents/` · `.memory/` · `specs/` |

AIOS loads stack-specific modules from `aios/stacks/<stack>/` and applies policy-appropriate detectors.

## AMX-specific stack behavior

For stacks `dotnet` · `java` · `php` · `cobol`: AIOS applies extra policies when AMX Revenue Accounting is the active policy:
- Credenciales hardcoded → detector CWE-798 obligatorio (Sprint 5.2)
- SQL injection → detector CWE-89 obligatorio (Sprint 5.x)
- SSL validation bypass → detector CWE-295 obligatorio
- Logging PII → detector CWE-532 obligatorio (Sprint 5.1)

Para `cobol` específicamente · AIOS tiene `aios/stacks/cobol/` que entiende AS400/iSeries patterns (caso Comisiones Directas · AEPTicketing).
