---
description: "Scaffold Nemesis pentest engagement desde el catalogo de 10 apps ACME"
triggers:
  - "scaffold engagement"
  - "nuevo pentest"
  - "red team setup"
  - "engagement nuevo"
  - "scaffold nemesis"
  - "prepare engagement"
---

# Nemesis Engagement Scaffold

Genera el paquete operacional (`roe.yaml` + `BRIEFING.md` + `PREFLIGHT.md`
+ `RUNBOOK.md`) para una o todas las apps del catalogo ACME Revenue
Accounting · FROZEN by default (2099 + signatures pending).

## Prereq · config aios

`aios-config.json` debe tener la seccion engagement:

```json
{
  "engagement": {
    "scaffold_script": "/path/absoluta/a/acme-hallazgos-audit/nemesis/nemesis-engagements/_catalog/scaffold.py",
    "quarter_default": "2026-Q2"
  }
}
```

## Pasos

1. Ver catalogo de apps disponibles:
   ```bash
   aios engagement --list
   ```
   Imprime tabla de 10 apps · owner · http_testable · status (
   `engagement_existing` · `pending_engagement` · `deferred` ·
   `pending_ownership`).

2. Scaffold UNA app:
   ```bash
   aios engagement --app 02-arc
   ```
   Genera 4 archivos bajo `nemesis-engagements/2026-Q2-arc-staging-dry-run/`.

3. Scaffold TODAS las pending (6 apps: ARC · BSP · CFDIs · SRG ·
   ASR · Robot):
   ```bash
   aios engagement --all
   ```

4. Quarter diferente:
   ```bash
   aios engagement --app 04-cfdis --quarter 2026-Q3
   ```

## Post-scaffold · flujo humano

Para cada engagement generado:

1. **Lee BRIEFING.md** · 12 secciones (contexto · scope · tecnicas ·
   safety · responsabilidades · deliverables).
2. **Envialo a los 3 firmantes** out-of-band (correo/DocuSign/papel):
   - Miatech Ciberseguridad (Carlos Reyes · agendar)
   - Etrive TPM
   - ACME Legal
3. **Recolecta firmas** · archiva bajo `nemesis-memory/<eid>/preflight/signatures/`.
4. **Completa PREFLIGHT.md** checklist (8 secciones · A-H).
5. **Ajusta `roe.yaml`**:
   - `starts_at` / `ends_at` a fechas reales Q2 2026
   - `scope_hosts` / `scope_cidr` con los staging reales
6. **Flip** `approver_signatures_verified: true` SOLO cuando los 4
   pasos anteriores esten completos.
7. **Ejecuta RUNBOOK.md** en la ventana autorizada.

## Safety invariants

- Todos los engagements generados arrancan FROZEN (2099)
- `approver_signatures_verified: false` por default
- 3 firmas `pending`
- `nemesis run` refusa ejecucion hasta flip manual
- 5 FORBIDDEN_TECHNIQUES hardcoded en blast_radius.py · no overridable
