# AIOS · Backlog · Bugs & Mejoras post-iteración

Items a resolver después de cerrar la iteración en curso (Sprint 5.3 · rama `feat/am-kiro-compat`).

---

## BUG-001 · Kiro UI no expone modos MIGRATION / LEGACY_MODERNIZATION

**Severidad**: MEDIA · afecta UX spec-driven pero hay workaround
**Origen**: Validación end-to-end con NoShow en Kiro IDE · 2026-04-20

### Síntoma
Al iniciar un spec en Kiro IDE para refactor ATOS-NOSHOW-ROBOT (.NET 4.7.2 → .NET 8 LTS), el diálogo "Input required" sólo ofrece **2 opciones**:
- `Build a Feature` (Recommended)
- `Fix a Bug`

Kiro incluso detecta el contexto correctamente en el prompt del diálogo: *"Based on your description, this sounds like a legacy modernization (refactoring an existing component). Is this a new feature or a bugfix?"* — pero no ofrece la tercera/cuarta opción.

### Causa raíz
El pack AIOS declara 4 modos en `manifest.json` → `capabilities.modes`:
```json
"modes": ["BUGFIX", "FEATURE", "MIGRATION", "LEGACY_MODERNIZATION"]
```
El router interno (ver `ai-memory/recent_decisions.md`) los puntúa correctamente (MIGRATION=19, LEGACY_MODERNIZATION=13, etc.), pero el UI de Kiro sólo renderiza las 2 opciones canónicas del host AM-KIRO.

### Workaround actual
Elegir `Build a Feature` y forzar el contexto en la descripción:
> "LEGACY_MODERNIZATION · refactor [app] [stack_origen] → [stack_destino] · aplicar constraints AMX retro 20-abr"

### Fix propuesto
Dos caminos (evaluar con Alberto Ibrahim Pedraza Cáscar · creador AM-KIRO):

1. **Opción A · extensión del host**: solicitar a AM-KIRO que lea `capabilities.modes` del manifest y renderice botones adicionales dinámicamente.
2. **Opción B · fallback en el pack**: el steering `01_router.md` de AIOS intercepta la clasificación inicial y re-mapea `FEATURE` → `MIGRATION`/`LEGACY_MODERNIZATION` según keywords (refactor, migrate, legacy, upgrade, .NET X → Y, etc.). No requiere cambios en Kiro pero pierde visibilidad en el UI.

### Impacto en AMX
Relevante porque el programa Armor incluye ≥4 apps en modernización (NoShow · SICOFAV · ARC · BSP · posiblemente más). Sin el fix, cada spec arranca con el modo equivocado y los steering rules de legacy (cobol/dotnet stacks + EARS acceptance criteria específicos) no se activan automáticamente.

### Tracking
- Reportar en correo a Alberto Ibrahim junto con propuesta de contribución packs
- Registrar también como issue cuando haya acceso a `OYN-AMX/am-kiro`

---

## BUG-002 · Kiro pide trust-list por cada here-string PowerShell en design.md

**Severidad**: BAJA · UX friction · no bloquea
**Origen**: Test 3 end-to-end NoShow · spec-driven generando design.md · 2026-04-20

### Síntoma
Cuando el agente de Kiro genera `design.md` en Windows usando PowerShell con el patrón `$content = @'...'@ ; Set-Content/Add-Content`, dispara el diálogo "Adding a command to the trust list..." **una vez por cada sección** (overview, architecture, components, data models, secrets = 5 prompts seguidos). Aparenta ser un bucle aunque es fricción secuencial.

### Causa raíz
El trust-list de Kiro toma la cadena completa del here-string como "full command" y no la normaliza por comando base (`$content = @'`). Cada sección tiene contenido distinto → hash distinto → prompt nuevo.

### Fix propuesto
Dos vías:

1. **Opción A · en el pack**: el steering `04_execution.md` del pack AIOS debe instruir al agente a escribir `design.md` en **una sola operación** (`Write` equivalente o un solo `Set-Content` con todo el contenido concatenado), no en chunks por sección. Esto reduce los prompts a 1.
2. **Opción B · en AM-KIRO host**: solicitar a Alberto Ibrahim que el trust-list reconozca `$content = @'` como base command independiente del heredoc payload.

Preferir Opción A — es un fix dentro del pack AIOS sin dependencia externa.

### Workaround actual
Al iniciar un spec con el pack AIOS, aprobar "Base · $content *" la primera vez para que las siguientes secciones no vuelvan a preguntar.

### Tracking
- Fix en el pack: ajustar `04_execution.md` para emitir `design.md` atómico
