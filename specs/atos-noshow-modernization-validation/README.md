# ATOS-NOSHOW Modernization · Validación End-to-End del Pack AIOS

**Fecha**: 2026-04-20
**Rama**: `feat/am-kiro-compat`
**Pack AIOS**: 1.7.1 · Sprint 5.3
**Policy activa**: `acme-finance_operations`
**Modo detectado**: `LEGACY_MODERNIZATION` (router score: 19)
**Origen**: Code real de ATOS-NOSHOW-ROBOT .NET 4.7.2 · Alonso · Finance Operations ACME

---

## Propósito

Esta carpeta contiene los 3 artefactos generados por Kiro IDE usando el pack AIOS + constraints ACME retro 20-abr, **como evidencia de validación end-to-end** del flujo spec-driven.

**No es código de producción** · es proof-of-concept del comportamiento del pack cuando el host AM-KIRO lo consume sobre código legacy real.

---

## Qué se validó

| Capacidad | Evidencia |
|---|---|
| 10 steering rules cargados | Kiro agent listó los 10 en `config.kiro` incluyendo `acme-constraints-retro-20abr.md` |
| Router detecta LEGACY_MODERNIZATION | Score MIGRATION=19 → mode correcto (aunque UI expone sólo Feature/Bugfix · BUG-001) |
| ACME constraints aplicados sin hand-holding | requirements.md + design.md mencionan EKS · AMX_Relay · CMK exclusiva · acme-r-* · sin ECS/SES/SNS |
| ADR opt A vs B (gate 3 ACME) | 5 ADRs en design.md: Runtime · Secrets · SFTP · SMTP · Orquestación batch |
| Trazabilidad Req X.Y · Design §Z | 109 tasks con referencias cruzadas completas |
| 9 gates ACME retro 20-abr como tasks BLOCKER | Phase 8 · 10 items marcados 🚫 (WIZ+Veracode+Prisma+Tenable separados) |
| Escritura atómica (workaround BUG-002) | design.md final generado en un solo `Set-Content` · cero prompts extra |

---

## Hallazgos para BACKLOG.md

Durante la validación se descubrieron 2 gaps UX del host Kiro:

- **BUG-001** · Kiro UI sólo expone 2 modos (Feature/Bugfix) · el pack declara 4
- **BUG-002** · Trust-list friction con PowerShell here-strings chunked · workaround en steering

Ambos están documentados en `/mnt/c/Users/eTriber/Temp/aios-framework/BACKLOG.md`.

---

## Artefactos

| Archivo | Líneas | Contenido |
|---|---|---|
| `requirements.md` | 317 | 15 requisitos EARS · funcionales · seguridad · NF · migración dual-run · ACME constraints |
| `design.md` | 999 | 9 secciones · C4 Mermaid · 5 ADRs · components + interfaces · data models · secrets + IAM · error handling · testing · deployment · observability · migration strategy |
| `tasks.md` | 191 | 109 tasks · 8 fases · 10 BLOCKERS (gates ACME) |

---

## Uso previsto

1. **Correo a Alberto Ibrahim Pedraza Cáscar** (creador AM-KIRO) · evidencia de que el pack produce outputs ACME-compliant end-to-end
2. **Referencia para Alonso** cuando arranque la implementación real de NoShow post-workshop SRG
3. **Base de comparación** para validar el comportamiento del pack cuando AM-KIRO exponga los 4 modos (fix de BUG-001)

---

## No hacer

- **No ejecutar las tareas de tasks.md desde esta carpeta** · la implementación de NoShow es scope de Alonso · arranca tras aprobaciones (OYN-ACME access · push rama · workshop SRG scope)
- **No modificar estos archivos** · son snapshot de validación · cualquier refinamiento posterior debe vivir en el repo de NoShow, no aquí
