# Discovery de la fase 1 · guía de comandos

`aios discovery-generate` produce los 9 entregables de la fase 1 de una modernización a partir de la
metadata del portafolio (`aios/core/portfolio.py`), del escaneo de seguridad embebido y del stack detectado
en el repositorio. `aios phase1-report` los consolida en un documento maestro.

> El portafolio del repositorio es **ficticio** (Acme Corp, 8 aplicaciones inventadas). Reemplaza `APPS`,
> `TIER_PATTERNS` y `CROSS_APP_BLOCKERS` en `aios/core/portfolio.py` para un portafolio real.

## Uso

```bash
aios discovery-generate --app billing --root ~/apps/billing           # 9 markdown
aios discovery-generate --app billing --root ~/apps/billing --pdf     # + PDF (requiere weasyprint)
aios discovery-generate --app billing --root ~/apps/billing --overwrite
aios phase1-report --app billing --root ~/apps/billing
```

Por omisión no sobrescribe documentos existentes (conserva lo que ya completó una persona).

## Entregables (`<root>/analisis/fase-1-discovery/`)

| Archivo | Contenido |
|---|---|
| `01_code_scan.md` | Hallazgos del escaneo por severidad y CWE |
| `02_hallazgos_mapped.md` | Hallazgos agrupados por CWE + espacio para la evaluación externa |
| `03_arq_as_is.md` | Stack del portafolio + stack detectado en el repo |
| `04_stakeholders.md` | Dueños funcional y técnico + roles de gobierno |
| `05_vulns.md` | Severidades + marcos aplicables (LFPDPPP, PCI-DSS, SOX, OWASP) |
| `06_deps.md` | Lockfiles detectados + versiones objetivo |
| `07_preguntas_nuevas.md` | Preguntas por dominio (arquitectura, datos, integraciones, seguridad, operación, negocio) |
| `08_bloqueadores.md` | Bloqueantes transversales del portafolio + específicos |
| `09_risk_register.md` | Riesgos por TIER + riesgos derivados de hallazgos CRITICAL/HIGH |

## Comandos relacionados

- `aios iterate --root . --strategies regex,ensemble` · escaneo exhaustivo antes del discovery
- `aios compliance-report --root . --format md` · hallazgos por marco regulatorio
- `aios org-analog --root .` · repos análogos del catálogo de la organización
