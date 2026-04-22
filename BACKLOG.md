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

---

## RFC-002 · 4 detectores de dominio faltantes (prioridad ALTA)

**Severidad**: ALTA · brecha de 75% entre framework y análisis humano experto
**Origen**: feedback usuario 2026-04-22 · análisis humano NoShow detectó 28 hallazgos · Mythos solo 7 (25% recall)

### Contexto

La validación LM-FRK70K reportó "100% precision/recall" · pero ese benchmark era contra un `SEED_EXPECTED_FINDINGS.json` autogenerado por el mismo proceso. Tautológico. El benchmark que importa es contra análisis humano experto de un proyecto real.

Resultado real: **framework capta 7 de 28 hallazgos (25%)** · los 21 restantes son bugs de dominio que los 72 detectores CWE estándar de Mythos no cubren por diseño. Mythos es CWE-scanner · no auditor de dominio.

### 4 detectores propuestos

#### RFC-002a · BUSINESS-HARDCODED-VALUES
Detecta valores de negocio hardcoded que deberían venir de datos runtime:
- Números de vuelo (`"829"`, patterns `^[0-9]{2,4}$` en contexto Flight/PNR)
- Route codes (`"MEX-TIJ"`, `"AIFA-CUN"`)
- SKUs pinned (`"CL-ECONOMY-FLEX"`)
- IDs de negocio específicos en literales

**Complejidad**: necesita heurística semántica · nombre de variable + contexto
**Ejemplo NoShow**: `if (pnr.FlightNumber == "829")` → debe ser `if (pnr.FlightNumber == config.NoShowTargetFlight)`

#### RFC-002b · CROSS-FOLDER-CONFIG-DRIFT
Detecta divergencia semántica entre configs de diferentes ambientes:
- `prod.config` vs `test.config` vs `qa.config` con mismas claves
- Reporta drift: keys presentes en uno y no en otro · valores "reales" en ambientes de test

**Complejidad**: cross-file analysis · necesita clustering por patrón de nombre
**Ejemplo NoShow**: `test.config` tiene los mismos secrets reales que `prod.config` → debería tener mocks

#### RFC-002c · SECRETS-IN-TEST-CONFIGS
Detecta secretos reales en archivos con sufijo/path de test:
- `*.test.config`, `*-qa.*`, `*/tests/`, `*/fixtures/` con literales que matchean forbidden_literals
- Whitelist heurístico: reconoce mocks (`mock-password`, `TEST_API_KEY`, `xxx-xxx-xxx`)

**Complejidad**: baja · combina forbidden_literals existente + glob del path
**Ejemplo NoShow**: `NoShowService.Tests.config` con password real de prod

#### RFC-002d · CODE-MARKED-FOR-REMOVAL
Detecta código stub/dead marcado para eliminación que sobrevivió iteraciones:
- `TODO: remove`, `TODO: delete`, `DEPRECATED`, `XXX-REMOVE`, `@deprecated` con fecha antigua
- Cross-reference con git blame (opcional) para detectar markers con > 6 meses

**Complejidad**: media · regex simple + opcional git history
**Ejemplo NoShow**: `// TODO: remove before release` de hace 8 meses en production code path

### Plan de implementación

- **v1.8.0** · RFC-002c + RFC-002d · rapid-fixes (regex + glob)
- **v1.8.1** · RFC-002a con heurística semántica básica (variable-name + type hint)
- **v1.8.2** · RFC-002b con cross-file diff · requiere cambio arquitectural (scanner pasa de per-file a workspace-level)

### Impacto esperado

Al cerrar estos 4 detectores · el recall contra análisis humano NoShow debería pasar de 25% → estimado 60-75%. El 25-40% restante siempre será bugs de dominio altamente específicos que requieren análisis humano experto. Esa brecha es intrínseca · no es fixeable con un scanner.

### Posicionamiento honesto (para narrative a Ibrahim)

**AIOS ES**:
- CWE-scanner automatizado (21/28 CWEs · 9 lenguajes)
- Generador de evidencia reproducible para gates AMX (WIZ/Veracode/Prisma/Tenable)
- Baseline mínimo en segundos sobre codebases sin análisis previo
- Red de seguridad · escalable a N apps

**AIOS NO ES** (y NUNCA debe venderse como):
- Sustituto del análisis humano experto de dominio
- Detector de anti-patrones de negocio
- Solución única pre-deploy · solo una capa de varias

**Narrativa correcta**: "Framework da evidencia automatizada reproducible para los 4 gates AMX (compliance). El análisis humano experto captura los bugs de dominio que ningún scanner detecta (vuelo hardcoded · drift de configs · lógica de negocio). Son complementarios · no sustitutos."

---

## BUG-004 · Discrepancia `aios release` vs `aios security-scan-staged`

**Severidad**: MEDIA · afecta reproducibilidad de evidencia
**Origen**: validación sesión limpia v2.1.0 · 2026-04-22 · usuario reportó 41 vs 22 findings entre los 2 comandos.

### Síntoma
- `aios release` reporta N findings sobre el workspace
- `aios security-scan-staged` reporta M findings (M < N típicamente)
- Los conjuntos de archivos barridos difieren · sin documentación clara del por qué

### Causa raíz probable
- `release` → `scan_directory()` · barre TODO el workspace (rglob)
- `security-scan-staged` → `scan_files()` · solo archivos pasados explícitamente (típicamente `git diff --cached --name-only`)

Cuando hay mucho código no staged, los counts difieren legítimamente. Pero el CLI no lo comunica.

### Fix propuesto
1. `aios security-scan-staged` debe loggear al inicio: "Scanning N staged files · full workspace tiene M files · counts no son comparables con `aios release`"
2. `aios release --detail` debe incluir una nota: "Full workspace scan · vs staged subset corre `aios security-scan-staged`"
3. Agregar a `aios doctor` un check: "discrepancia staged vs release si > 20% delta"

### Tracking
- v2.1.1 · agregar logging warning en staged command

---

## BUG-005 · Ontology seed solo cubre `forbidden_literals` · no rule_ids de Mythos

**Severidad**: ALTA · usuarios ven 80%+ de findings como `unclear`
**Origen**: validación sesión limpia v2.1.0 · 2026-04-22 · 16/41 findings clasificados como `unclear` en carpeta test.

### Síntoma
El ontology seed (`aios/policies/amx-revenue-accounting/ontology.yaml`) inicialmente solo tenía entries por `literal` (PERRO_ROBOTICO, ATOS5246, etc). Cuando un detector de Mythos emite un finding con rule_id que no está en el catálogo (ej. `CREDENTIAL-PLAINTEXT-WEBCONFIG`, `STATIC-PATH-TRAVERSAL-CSHARP`), el ontology cae al default_classification que es `unclear`, pasando a review queue en vez de auto_fix.

Resultado: review queue saturado de falsos unclears · UX pobre · el Nivel 1 no cumple su promesa de clasificar CWEs estándar como `bug`.

### Fix (v2.1.1 · commit pendiente)
Ampliar el ontology seed con 12 entries nuevas que mapean `rule_id` → classification:
- CWE-522/798 · CREDENTIAL-PLAINTEXT-* → bug
- CWE-89 · STATIC-SQL-* → bug
- CWE-78 · STATIC-CMD-* → bug
- CWE-22 · STATIC-PATH-TRAVERSAL-* → bug
- CWE-502 · STATIC-PICKLE-* → bug
- CWE-611 · STATIC-XXE-* → bug
- CWE-79 · STATIC-XSS-* → bug
- CWE-312 · STATIC-CLEARTEXT-* → bug
- CWE-547 · HARDCODED-INTERNAL-HOSTNAME → migration_candidate
- CWE-287 · STATIC-AUTH-BYPASS-* → bug · auto_fix=false (requiere review humano)
- CWE-770 · STATIC-NO-TIMEOUT · UNBOUNDED-LOOP → bug
- CWE-327 · STATIC-MD5/SHA1/WEAK-* → bug

Con esto, la mayoría de los findings CWE estándar quedan clasificados correctamente. Review queue solo se llena con verdaderos unclears o business_rules.

### Validación pendiente
Re-correr el análisis sobre el mismo workspace post-v2.1.1 · esperado: unclear count baja de 16 a ≤3.

---

## RFC-003 · Domain-awareness · de scanner genérico a asistente con contexto

**Severidad**: CRÍTICA · es la diferencia entre "framework juguete" y "herramienta profesional"
**Origen**: feedback usuario 2026-04-22 · "¿qué me asegura que el refactor no sea genérico?"

### El problema fundamental

Hoy Mythos detecta patterns CWE-estándar · pero no distingue entre:
- Hardcoded value que es **BUG** (secret · credential · injection)
- Hardcoded value que es **REGLA DE NEGOCIO** (vuelo 829 específico del dominio NoShow · ruta específica · ID acordado con un tercero)

El refactor auto-mode asume que todo detected finding es bug · aplica fix genérico · tests de regresión son string-level (valida que el pattern no reaparezca · no que el behavior sea correcto). Resultado: refactor genérico puede introducir bugs nuevos que pasan libres hasta deploy.

**El análisis humano es el único filtro real hoy. Sin humano · el framework rompe dominio.**

### 8 capacidades faltantes

1. **Domain ontology** · catálogo AMX versionado (`amx-domain-ontology.yaml`) con clasificación por pattern (bug / business_rule / unclear) · auto_fix_allowed · fix_template · evidence_required
2. **Intent classification pre-fix** · LLM call o humano pregunta: "¿este valor es bug o intent?" antes de refactorizar
3. **Characterization tests antes del refactor** · captura behavior real con inputs · genera suite · refactor rollback-safe si rompe contract
4. **Cross-file semantic analysis** · call-graph + semantic clustering · detecta drift entre archivos · impacto de un cambio en otros files
5. **Stakeholder-in-the-loop explícito** · auto_fix_safe vs requires_review · pausa en decisiones no-obvias
6. **Git blame + commit context como signal** · clasificar intent con historia del código
7. **Behavior-preserving tests (no string-preserving)** · tests validan contract · no ausencia del pattern
8. **Dual-path artifacts** · PR técnico + business review doc por cada fix

### 4 niveles de implementación (ROI vs esfuerzo)

| Nivel | Qué cubre | Esfuerzo | ROI |
|---|---|---|---|
| **Nivel 1** · Domain ontology (capacidad 1) | classificación pre-fix básica | 2-3 días | 🟢 Alto · cambio dramático |
| **Nivel 2** · LLM classifier per-finding (capacidades 2, 6) | intent classification con context | 1-2 semanas | 🟢 Alto · reduce 80% FP dominio |
| **Nivel 3** · Characterization tests (capacidades 3, 7) | behavior-preserving · rollback auto | 3-4 semanas | 🟡 Medio · complejo por lenguaje |
| **Nivel 4** · Stakeholder split (capacidades 5, 8) | auto_fix_safe vs requires_review | 2-3 semanas | 🟢 Alto · cambio cultural del flujo |

Cross-file semantic analysis (capacidad 4) es transversal · se implementa gradualmente.

### Status quo honesto que debo comunicar

- Sin Nivel 1-2 · **no confiar en auto-mode sobre codebases críticos sin review humano**
- Framework hoy = red de seguridad CWE · **no** refactor agent autónomo en producción
- El humano es el centro · el framework acelera · nunca sustituye

### Plan propuesto

- **v1.8 · Nivel 1**: `amx-domain-ontology.yaml` + helper `classify_finding(finding, ontology) -> {allowed, pause, skip}` · 2-3 días
- **v1.9 · Nivel 2**: LLM classifier · `classify_finding_with_llm(finding, git_context) -> intent` · 1-2 semanas
- **v2.0 · Nivel 3-4**: characterization + stakeholder split · 1-2 meses · requiere piloto con AMX para validar antes

### Conclusión

Este RFC es el **más crítico** del backlog · cierra la brecha entre "framework juguete" y "herramienta profesional". Sin esto · todo el pre-deploy (CI/CD · gates · release_gate) es teatro: el código refactorizado puede tener bugs de dominio intactos o nuevos · y ningún gate los detecta.

Prioridad: ALTA · pre-requisito para cualquier piloto con cliente real (NoShow · otros AMX).
