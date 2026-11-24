---
inclusion: fileMatch
fileMatchPattern: ['pyproject.toml', 'package.json', 'pom.xml', 'csproj', 'Gemfile', 'Cargo.toml', 'go.mod']
---

# AIOS · Stack Auto-Detection

When a project is opened with AIOS (via `aios init`) · the framework detects installed stacks by scanning for marker files:

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

## Mandatory detectors per stack

For stacks `dotnet` · `java` · `php` · `cobol`, the security gate always runs:
- Hardcoded credentials → CWE-798
- SQL injection → CWE-89
- SSL validation bypass → CWE-295
- PII in logs → CWE-532

`aios/stacks/cobol/` understands IBM i (AS/400) and z/OS COBOL source layouts.
