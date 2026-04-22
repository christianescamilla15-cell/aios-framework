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

---

## RFC-001 · STATIC-CMD-SHELL-TRUE detector · verificación

**Severidad**: INFORMACIONAL (no es bug)
**Origen**: FINAL_REPORT_LM_FRK70K.md · recomendación R3 · 2026-04-22

### Observación
El FINAL_REPORT del refactor 70K reportó que el detector `STATIC-CMD-SHELL-TRUE` activaba en `shell=False` (falso positivo de 1 archivo). Revisión del código confirma que **el regex actual es correcto**:

```python
re.compile(r"""subprocess\.[a-z]+\([^)]*shell\s*=\s*True""")
```

El regex requiere literal `shell=True` · no matchea `shell=False`. El falso positivo reportado vino de OTRO detector (probable `STATIC-CMD-SHELL-TRUE` fue confusión con `STATIC-PICKLE-DESERIALIZATION` u otro) o del scanner de `forbidden_literals` sobre comentarios de trazabilidad.

### Resolución
Cerrado como NO-BUG · el regex `[^)]*shell\s*=\s*True` es el filtro correcto. El caso real (comentarios con `shell=False`) queda resuelto por R1 (`exclude_comment_lines` en commit `0943cb9`).

### Evidencia
Test local sobre fragmentos:
- `subprocess.run("x", shell=True)` → ✅ match (CRITICAL)
- `subprocess.run("x", shell=False)` → ✅ no match
- `# antes usabamos shell=False` (comment) → ✅ no match (filtro v1.7.2)

---

## BUG-003 · Kiro UI · checkpoint automático entre fases

**Severidad**: BAJA · afecta UX de sesiones muy largas
**Origen**: FINAL_REPORT_LM_FRK70K.md · recomendación R7 · 2026-04-22

### Síntoma
Durante el refactor LM-FRK70K (3.5h · 10 módulos · 9 commits), Kiro requirió múltiples "continua" del usuario cuando llegaba al límite de contexto de turn. Esto fragmenta la ejecución autónoma declarada en auto-mode y consume cuota de créditos por re-lecturas.

### Causa raíz (hipótesis)
Kiro no persiste estado de "fase en progreso" entre turns. Al llegar al límite del context window, pierde el plan explícito y espera instrucciones nuevas.

### Fix propuesto (AIOS side)
Agregar a `ai-memory/active_workstream.md` un campo `## Checkpoint` con:
- `phase_completed`: última fase cerrada
- `phase_in_progress`: fase actual + sub-step
- `next_action`: comando exacto para retomar
- `last_commit`: hash del último commit atómico

Cuando el usuario escribe "continua" · el router lee el Checkpoint y emite el prompt exacto internamente. Requiere steering rule en `04_execution.md` que obligue a escribir/actualizar el Checkpoint después de cada build-gate PASS.

### Fix propuesto (Kiro host side · fuera de nuestro control)
Auto-resumption cuando el usuario hace "continua" · que Kiro recargue automáticamente el `active_workstream.md` + `Checkpoint` sin pedir intervención.

### Workaround actual
Al "continua" · decir también "lee el último commit en git y sigue desde donde quedaste".

### Tracking
- Requiere feature grande · iteración futura (post-Sprint 5.3)
- Dependency: Alberto Ibrahim si queremos Auto-resumption del host

---

## NOTA · Kiro UI · límite de context/cuota

**Estado**: SIN ACCIÓN (fuera de scope AIOS · observado)
**Origen**: FINAL_REPORT_LM_FRK70K.md · recomendación R6 · 2026-04-22

Kiro Free Bonus 500 créditos se agota rápido en workspaces grandes (70K LoC pre-carga context cada turn). Cuando se agota, Kiro retorna "Too many requests". Solo mitigable desde el host Kiro (aumentar cuota · context caching · prompt compaction). Documentado para evidencia · no es fix del pack AIOS.

Workaround durante la sesión:
1. Dividir prompts grandes en chunks más pequeños (5 chunks vs 1 mega-prompt)
2. Ejecutar partes boilerplate desde WSL/terminal (CI/CD templates · Dockerfiles) sin pasar por el agente
