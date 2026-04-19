---
description: "Genera markdown agregado con release gate + last arena + SARIF + engagements"
triggers:
  - "aios report"
  - "aggregate report"
  - "reporte consolidado"
  - "status de seguridad"
  - "security summary"
  - "project security status"
---

# AIOS Aggregate Report

Consolida todos los outputs de seguridad del proyecto en un markdown
bajo `reports/aios_report_<timestamp>.md` · util para handoff,
standups, o compartir con stakeholders.

## Pasos

```bash
aios report
```

Genera 4 secciones:

1. **Release Gate** · resultado de `aios release` checks + top
   security findings (cwe · rule_id · file:line).
2. **Last Arena self-play run** · verdict + target + timestamp del
   ultimo run leido de `ai-memory/security_findings.md`.
3. **Arena SARIF findings (recent runs)** · tabla con los 5 runs mas
   recientes · rules · findings · nemesis confirmed · total.
4. **Nemesis engagements** · lista de engagements scaffolded con
   estado (signed YES/NO · frozen/active window).

## Output

- Archivo · `reports/aios_report_<ISO-timestamp>.md`
- Summary en terminal · icono por section status (OK · !! · XX · --)

## Cuando usarlo

- **Daily standup**: `aios report` + pegar el summary en Slack
- **Handoff**: `aios report` + compartir el MD con el siguiente
  operador
- **Pre-demo**: generar justo antes de mostrar state al cliente
- **Auditoria**: los reports historicos quedan en `reports/` con
  timestamp · history linear

## Depende de · pero no ejecuta

Este comando NO ejecuta arena/mythos/nemesis · solo lee:
- Release gate (via `check_release_readiness`)
- `ai-memory/security_findings.md` (escrito por `aios arena`)
- `arena-memory/runs/*/findings.sarif` (si existen)
- `nemesis-engagements/*/roe.yaml` (para estado signed/frozen)

Para refresh de data, corre `aios arena` y `aios release` primero.
