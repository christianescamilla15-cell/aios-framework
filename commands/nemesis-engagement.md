---
description: "Scaffold de un engagement de pentest de Nemesis desde el catálogo de apps"
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
+ `RUNBOOK.md`) para una o todas las apps del catálogo del scaffolder
externo · FROZEN by default (2099 + signatures pending).

## Prereq · config aios

`aios-config.json` debe tener la seccion engagement:

```json
{
  "engagement": {
    "scaffold_script": "/ruta/absoluta/a/security-lab/nemesis/nemesis-engagements/_catalog/scaffold.py",
    "quarter_default": "2026-Q2"
  }
}
```

## Pasos

1. Ver catalogo de apps disponibles:
   ```bash
   aios engagement --list
   ```
   Imprime tabla de apps · owner · http_testable · status (
   `engagement_existing` · `pending_engagement` · `deferred` ·
   `pending_ownership`).

2. Scaffold UNA app:
   ```bash
   aios engagement --app 02-orders
   ```
   Genera 4 archivos bajo `nemesis-engagements/2026-Q2-orders-staging-dry-run/`.

3. Scaffold TODAS las pendientes:
   ```bash
   aios engagement --all
   ```

4. Quarter diferente:
   ```bash
   aios engagement --app 03-shipping --quarter 2026-Q3
   ```

## Post-scaffold · flujo humano

Para cada engagement generado:

1. **Lee BRIEFING.md** · 12 secciones (contexto · scope · tecnicas ·
   safety · responsabilidades · deliverables).
2. **Envialo a los 3 firmantes** out-of-band (correo/firma electrónica/papel):
   - Ciberseguridad del dueño del sistema
   - Gerencia técnica del programa
   - Jurídico
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
