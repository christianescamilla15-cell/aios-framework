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
> "LEGACY_MODERNIZATION · refactor [app] [stack_origen] → [stack_destino] · aplicar constraints ACME retro 20-abr"

### Fix propuesto
Dos caminos (evaluar con Alberto Ibrahim Pedraza Cáscar · creador AM-KIRO):

1. **Opción A · extensión del host**: solicitar a AM-KIRO que lea `capabilities.modes` del manifest y renderice botones adicionales dinámicamente.
2. **Opción B · fallback en el pack**: el steering `01_router.md` de AIOS intercepta la clasificación inicial y re-mapea `FEATURE` → `MIGRATION`/`LEGACY_MODERNIZATION` según keywords (refactor, migrate, legacy, upgrade, .NET X → Y, etc.). No requiere cambios en Kiro pero pierde visibilidad en el UI.

### Impacto en ACME
Relevante porque el programa Armor incluye ≥4 apps en modernización (NoShow · FLEET_OPS_APP · ARC · BSP · posiblemente más). Sin el fix, cada spec arranca con el modo equivocado y los steering rules de legacy (cobol/dotnet stacks + EARS acceptance criteria específicos) no se activan automáticamente.

### Tracking
- Reportar en correo a Alberto Ibrahim junto con propuesta de contribución packs
- Registrar también como issue cuando haya acceso a `OYN-ACME/am-kiro`

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
- Generador de evidencia reproducible para gates ACME (WIZ/Veracode/Prisma/Tenable)
- Baseline mínimo en segundos sobre codebases sin análisis previo
- Red de seguridad · escalable a N apps

**AIOS NO ES** (y NUNCA debe venderse como):
- Sustituto del análisis humano experto de dominio
- Detector de anti-patrones de negocio
- Solución única pre-deploy · solo una capa de varias

**Narrativa correcta**: "Framework da evidencia automatizada reproducible para los 4 gates ACME (compliance). El análisis humano experto captura los bugs de dominio que ningún scanner detecta (vuelo hardcoded · drift de configs · lógica de negocio). Son complementarios · no sustitutos."

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
El ontology seed (`aios/policies/acme-finance_operations/ontology.yaml`) inicialmente solo tenía entries por `literal` (PERRO_ROBOTICO, ATOS5246, etc). Cuando un detector de Mythos emite un finding con rule_id que no está en el catálogo (ej. `CREDENTIAL-PLAINTEXT-WEBCONFIG`, `STATIC-PATH-TRAVERSAL-CSHARP`), el ontology cae al default_classification que es `unclear`, pasando a review queue en vez de auto_fix.

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

## RFC-004 · 4 detectores nuevos derivados de análisis NoShow real (ATOS-NOSHOW-ROBOT)

**Severidad**: ALTA · captura 4 clases de hallazgos reales que AIOS no ve hoy
**Origen**: análisis sesión-limpia sobre ATOS-NOSHOW-ROBOT + NoshowReport · 2026-04-22. Framework detectó 3 findings reales vs ~7 detectables humano = 40% coverage · consistente con calibración previa 25-40% CWE-scanner+gates.

Los 4 gaps descubiertos son **patrones de infosec reales** que escapan a CWE estándar · muy valiosos para ACME y cualquier enterprise con builds/deployments múltiples.

### RFC-004a · CROSS-COPY-DRIFT-DETECTOR

Detecta divergencia entre copias del mismo servicio (`source-tree/` vs `build-output/` vs `prod-deployed/`). Caso real NoShow:
- Target framework: source 4.7.2 vs build 4.6.1
- UserName/Password divergentes entre source y test config
- Sabre cert paths distintos
- Distribution lists de email diferentes

**Implementación sugerida**: scanner mode `--compare <dir1> <dir2>` que para cada par de archivos con nombre similar (fuzzy match · ej. `App.config` en ambos) hace diff semántico de keys/values.

### RFC-004b · CREDENTIAL-BYTE-IDENTITY-DETECTOR

Detecta secretos **byte-idénticos** entre `prod.config` y `test.config` · indica que test está usando credenciales reales (no mocks). Caso NoShow:
- DB AIDX password byte-idéntica en prod + test + source
- SFTP passphrase byte-idéntica

**Implementación**: hash de cada value que matchee forbidden_literal pattern · si 2+ archivos tienen el mismo hash en keys con nombre `password|secret|token|key`, flag CRITICAL.

**Por qué es valioso**: este es el clásico "test ambiente compartido" que explota muchos breaches · ningún SAST comercial lo detecta de forma automatizada.

### RFC-004c · THIRD-PARTY-EXFIL-HEURISTIC · CERRADO v2.3.0

Detecta distribución de datos a dominios no-corporativos desde código de producción. Caso NoShow:
- Dist lists con emails `@miatech.net` (third-party · no ACME)

**Implementación**: scanner busca literales `user@dominio.tld` · compara contra whitelist de dominios corporativos (configurable en aios-config.json `corporate_domains: ["acme.com", "acmeair.com", ...]`). Los que no matchean · flag HIGH.

**Caveat**: puede tener FPs para integraciones legítimas (auditores · partners). Solución: whitelist explícita por proyecto.

**Entregado** · `aios/core/exfil_detector.py` + CLI `aios exfil --corporate ...` · detecta emails · URLs · smtp/ftp hosts no whitelisted · env_hint automático (prod/test/dev) · severity HIGH en prod · MEDIUM genérico · INFO en test.

### RFC-004d · RUNTIME-DATA-FILE-SCANNER · CERRADO v2.4.0

Extiende el scan a archivos que hoy quedan fuera por diseño pero contienen data sensible:
- `Email.html` templates (pueden tener PII · placeholders vs real)
- `files/*.txt` (PNRs · tickets)
- `logs/*.log` (raramente versionados · pero en build outputs aparecen)

**Implementación**: categoria nueva `runtime_data` con detectores específicos · scan opt-in con `--include-runtime-data`. No cambiar default (evita noise).

**Entregado** · `aios/core/runtime_data_scanner.py` + CLI `aios runtime-data` · 10 detectores: PNR · email · PAN (Luhn-checked) · CURP · RFC-MX · SSN · passport · phone · JWT · session token · IP privada · extensiones HTML/TXT/LOG/CSV/EML/DAT + path hints (`files/`, `templates/`, `logs/`).

### Prioridad

- **Tier 1** (v2.2.0 · CERRADO): 004a + 004b · son los 2 más impactantes · requieren rediseño minor del scanner (workspace-level vs file-level).
- **Tier 2** (v2.3.0 · CERRADO): 004c · corporate_domains whitelist + heuristic simple.
- **Tier 3** (v2.4.0 · CERRADO): 004d · scan extendido a runtime data · nuevos detectores PII + PAN + tokens.

### Impacto esperado al cerrar RFC-004

Coverage esperado contra análisis humano:
- Actual (v2.1.1): 25-40% en workspaces reales
- v2.2.0 (+ 004a + 004b): ~60% (agrega drift + credential equivalence · ambos son ~15% del valor perdido)
- v2.3.0 (+ 004c): ~70%
- v2.4.0 (+ 004d): ~80%

El 20% restante siempre serán bugs de dominio altamente específicos que requieren humano (lógica de negocio · integración cross-module · flujos de autorización). Esa brecha es intrínseca · no es fixeable con un scanner · **documentado explícitamente como límite del framework**.

---

## BUG-006 · __version__ hardcoded desactualizado en aios/__init__.py

**Severidad**: BAJA · solo cosmético pero daña credibilidad
**Origen**: validación NoShow 2026-04-22 · `aios version` reportó v1.7.1 aunque package instalado era 2.1.1.

### Causa
Los bumps de version v1.7.2 → v2.1.1 tocaban `pyproject.toml`, `manifest.json`, `.kiro/settings/aios-settings.json` pero NO `aios/__init__.py` que tenía string hardcoded `__version__ = "1.7.1"`.

### Fix (v2.1.2 · commit pendiente)
`aios/__init__.py` ahora lee versión dinámicamente de `importlib.metadata.version("aios-kiro")` · sincroniza siempre con pyproject.toml. Fallback hardcoded `"2.1.2"` solo si el package no está instalado (dev local fresh clone).

### Prevención a futuro
Leer de pyproject.toml es la solución permanente · ningún script de bump puede "olvidar" el `__init__.py`. Versionado single-source-of-truth.

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

1. **Domain ontology** · catálogo ACME versionado (`acme-domain-ontology.yaml`) con clasificación por pattern (bug / business_rule / unclear) · auto_fix_allowed · fix_template · evidence_required
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

- **v1.8 · Nivel 1**: `acme-domain-ontology.yaml` + helper `classify_finding(finding, ontology) -> {allowed, pause, skip}` · 2-3 días
- **v1.9 · Nivel 2**: LLM classifier · `classify_finding_with_llm(finding, git_context) -> intent` · 1-2 semanas
- **v2.0 · Nivel 3-4**: characterization + stakeholder split · 1-2 meses · requiere piloto con ACME para validar antes

### Conclusión

Este RFC es el **más crítico** del backlog · cierra la brecha entre "framework juguete" y "herramienta profesional". Sin esto · todo el pre-deploy (CI/CD · gates · release_gate) es teatro: el código refactorizado puede tener bugs de dominio intactos o nuevos · y ningún gate los detecta.

Prioridad: ALTA · pre-requisito para cualquier piloto con cliente real (NoShow · otros ACME).

---

## v3.7.4 SHIPPED · 5 detector quality gaps cerrados · 2026-04-27

**Branch**: `feat/v3.7.4-detector-quality-gaps`
**Origen**: FLEET_OPS_APP refactor triangulaciones T3..T6 (`docs/security-reviews/FINDINGS_TRIANGULATION.md` §13–§17)
**Tests**: 419/419 ✅ (+18 nuevos vs 401 baseline v3.7.3)
**Stat**: 8 files modified · +417 -4

### Gaps cerrados (los 5 que estaban siendo trackeados implícitamente en triangulaciones FLEET_OPS_APP)

| ID | Severidad | Finding pre-fix | Fix v3.7.4 | Test cover |
|---|---|---|---|---|
| **G-AUTH-CLASS-LEVEL** | ALTA | detector `AUTH-MISSING-NET-CONTROLLER` ignoraba `[Authorize]` a nivel clase · FPs HIGH en FLEET_OPS_APP `FacturasController` y `ConciliacionesController` | `_class_has_authorize_attr` (12-line lookback antes de declaración `class`) en `aios/core/security_gate.py` | `test_auth_missing_skipped_when_class_level_authorize` |
| **G-AUTH-LOOKAHEAD** | ALTA | detector consumía greedy el stack de attributes `[^\]]*\]` y luego `(?!Authorize)` solo veía la siguiente línea · `[HttpPost]\n[Authorize(Roles=...)]\npublic` matcheaba como FP | `_method_has_authorize_attr_inline` inspecciona el span match completo | `test_auth_missing_skipped_when_authorize_inline_after_http` + negative regression |
| **G-EXCEPTION-WHEN-FILTER** | MEDIA | detector `STATIC-GENERIC-EXCEPTION-CATCH-CSHARP` flageaba MED a `catch (Ex) when (ex is not OperationCanceledException)` · diseño defendible, no catch-all sloppy | `_catch_has_when_filter` degrada MED→LOW (similar al downgrade existente por logging) | `test_generic_catch_with_when_filter_degrades_to_low` + negative |
| **G-SUPPRESSIONS-ITERATE** | ALTA | `aios iterate` y `aios compliance-report` NO consumían `aios-suppressions.json` · sólo `aios release` lo hacía · suppressions documentadas seguían apareciendo en cada run | `_apply_iterate_suppressions` al final de `IterativeScanner.run()` + `suppressed_count` en `IterativeReport.to_dict()` · `cmd_compliance_report` también consume waivers | 6 tests integración (`tests/test_iterative_scanner_suppressions.py` nuevo) |
| **G-RULE-ID-UNIFY** | MEDIA | `aios-suppressions.json` con `rule="CWE-547"` no matcheaba findings `rule_id=HARDCODED-INTERNAL-HOSTNAME` aunque ambos comparten CWE · UX inconsistente con SARIF/Sonar (que usan `rule`) | `load_suppressions` acepta `rule` como alias de `rule_id` · `Suppression.matches()` fallback CWE case-insensitive cuando `rule_id` parece `CWE-NNN` | 7 tests (alias · CWE fallback · case insensitive · legacy FLEET_OPS_APP-shape) |

### Helpers nuevos en `aios/core/security_gate.py`

```python
_AUTHORIZE_ATTR_PATTERN = re.compile(
    r"\[\s*(?:Authorize|RequireAuthorization|AuthorizeRoles|"
    r"ApiKeyRequired|CustomAuth|AuthorizePolicy)(?:\s*\(|\s*\])"
)

def _class_has_authorize_attr(content, member_match_start, max_lookback_lines=12)
def _method_has_authorize_attr_inline(matched_span)
def _catch_has_when_filter(content, catch_match_end, max_span=200)
```

Wire-up en `scan_directory` y `scan_files` (cobertura ambos paths · pre-commit hook + full repo scan).

### Cambios subcommands

| Subcommand | v3.7.3 | v3.7.4 |
|---|---|---|
| `aios release` | consume `aios-suppressions.json` | igual |
| `aios iterate` | NO consume waivers | **consume + reporta `suppressed_count` en JSON y stop_reason** |
| `aios compliance-report` | NO consume waivers | **consume + log inline** |

### Smoke validación vs FLEET_OPS_APP

| Métrica | T6 pre-fix v3.7.3 | T6 post-fix v3.7.4 | Δ |
|---|---|---|---|
| HIGH | 2 (FP × 2) | **0** | -2 ✅ |
| MEDIUM | 5 | 3 (todos genuinos ACME-CDK tagging) | -2 |
| `suppressed_count` (JSON) | 0 (gap) | **1** (T3-FP-001b activo via CWE fallback) | ✅ |
| `BalanceadorUrlValidator.cs:144` en compliance LFPDPPP/PCI | sí (FP propagado) | **no** (suppressed) | ✅ |

### Impacto framework-wide

- Beneficia las 10 apps Finance Operations (no sólo FLEET_OPS_APP) · cualquier .NET ApiController con `[Authorize]` clase + `[Authorize(Roles=...)]` método ya no FP
- `catch ... when` C# 6+ pattern reconocido como diseño correcto cross-codebase
- Suppressions retroactivamente aplicables a iterate/compliance · cierra divergencia release vs reporting
- Alias `rule` baja la barrera de entrada para teams que migran desde SARIF/Sonar/CodeQL

### Files modified

```
aios/__init__.py                                             |   2 +-
aios/cli/main.py                                             |  15 +
aios/core/iterative_scanner.py                               |  58 +
aios/core/security_gate.py                                   | 106 +
aios/core/suppressions.py                                    |  23 +
pyproject.toml                                               |   2 +-
tests/test_security_gate.py                                  | 133 +
tests/test_suppressions.py                                   |  82 +
tests/test_iterative_scanner_suppressions.py (nuevo)         |  98 +
```

### Patrón operativo cementado

> **Detector quality regla**: cada vez que un detector AIOS reporta un FP en una app real, abrir gap en framework backlog (no sólo suppression táctica). Suppressions cubren la app específica · gaps framework cubren el universo de apps ACME.

Aplicado: 5 gaps de FLEET_OPS_APP → 5 fixes de framework v3.7.4 que benefician las 10 apps R.A.

### Pendientes post-shipping

- ⏸ Tag `v3.7.4` post-merge a `main`
- ⏸ Push origin (christianescamilla15-cell · público)
- ⏸ Push acme (acme-team · privado · regla ACME)
- ⏸ Smoke vs apps adicionales R.A. cuando estén disponibles (Robot · SRG · BSP refactor)

---

## v3.7.5 · 3 framework gaps cerrados (T8 close · 2026-04-27)

Derivado de FLEET_OPS_APP triangulación-8 (`docs/security-reviews/FINDINGS_TRIANGULATION.md` §20-B) · 3 gaps detectados durante AIOS T8 run sobre repo FLEET_OPS_APP post-T7 close:

### G-PATH-NORMALIZATION (T8-N1) · MED · CWE-1110

**Problema**: `Suppression.matches()` comparaba `self.file != finding.file` con strings exactos. Cuando `aios-suppressions.json` declara `file: "infra/cdk-pipeline/stacks/x.py"` (repo-root path) pero `aios iterate --root infra/cdk-pipeline` emite finding con `file: "stacks/x.py"` (relative-to-root) · matcher fallaba · `suppressed_count=0` cuando deberían aplicarse 3.

**Fix**: helper `_paths_match()` en `aios/core/suppressions.py` con normalización separator-aware:
1. Exact match (caso normal)
2. El path largo termina con `/` + path corto (scope-reduced match)
3. Backslash → forward slash (Windows path tolerance)

**Test coverage**: 5 tests (`test_paths_match_helper_*` + `test_t8_n1_e2e_*`) en `tests/test_suppressions.py`.

### G-REGEX-TIMEOUT (T8-N3) · MED · operacional

**Problema**: `aios iterate --root infra/k8s/` colgaba indefinidamente (>40min · 90% CPU) sobre `fleet_ops_app-deployment.yaml` (147 LOC YAML multiline) · regex catastrophic backtracking · gap framework documentado doble evidencia (iterate + compliance-report).

**Fix**: helper `_safe_finditer()` en `aios/core/security_gate.py` usa `signal.SIGALRM` con timeout configurable (default 2s · override `AIOS_REGEX_TIMEOUT_SECONDS`):
- Unix-only protection (Linux/Mac/WSL · cubre 99% AIOS prod runs)
- Windows fallback: direct `pattern.finditer()` sin timeout (acceptable trade-off · dev local only)
- Si regex excede timeout · log warning + return `[]` · scan continúa con próximos detectores

**Test coverage**: 4 tests (`test_safe_finditer_*`) en `tests/test_security_gate.py`.

**Smoke test FLEET_OPS_APP**: `aios iterate --root infra/k8s` ahora termina en <60s (antes hung indefinidamente).

### T8-N2 · compliance-report `--output` CWD · LOW · CWE-22

**Problema**: `aios compliance-report --root src --output reports/x.md` resolvía `--output` relative to `--root`, escribiendo a `src/reports/x.md` con mensaje engañoso `Written: reports/...`. Inconsistente con expectation Unix estándar (relative paths from CWD).

**Fix**: en `aios/cli/main.py` 2 sites donde `dest = root / dest` cambiado a `dest = Path.cwd() / dest`. Display `rel = dest.relative_to(Path.cwd())` para mensaje correcto.

**Smoke test FLEET_OPS_APP**: `aios compliance-report --root src --output /tmp/x.md` y `--output reports/x.md` ambos resuelven correctamente desde CWD.

### Métricas v3.7.5

| Métrica | v3.7.4 | v3.7.5 |
|---|---|---|
| Tests pass | 419 | **428** (+9) |
| Detectores ACME-specific | 29 | 29 (mejoras de calidad) |
| Cross-app applicability | sí · base | sí · más robusto |

### Smoke validación post-fix vs FLEET_OPS_APP

- `aios iterate --root infra/k8s` · ✅ termina <60s (antes hung indefinido)
- `aios compliance-report --root src --output reports/x.md` · ✅ escribe en `<repo-root>/reports/x.md` (antes `src/reports/`)
- Suppressions T7-FP-003-KMS/LOGS/S3 · esperado aplicar correctamente al re-correr FLEET_OPS_APP T8 con `--root infra/cdk-pipeline` · `suppressed_count: 3` (antes 0)

### Pendiente post-v3.7.5

- ⏸ Commit + merge main + tag `v3.7.5` + push origin/acme (cross-app · pendiente confirmación user)
- ⏸ Update version en `pyproject.toml` + `aios/__init__.py` (DONE)

---

## v3.8.0 Governance Pack · Drift items detectados pre-release · 29-abr-2026

**STATUS 29-abr noche**: G-DRIFT-1 + G-DRIFT-3 cerrados en v3.8.2 · CFDIs OUT cementado.

Antes de publicar v3.8.0, audit cruzado contra repos ACME detectó 3 alignment gaps que NO bloquean release pero deben tratarse en v3.8.1.

### G-DRIFT-1 · ADEA naming exception · MEDIUM · alineación BO-ACME

**Origen**: `BO-ACME/CS_Scripts@v0.12.0` · `compliance/check_f06_compliance.py` (Fer Pérez · 2026-04-29 12:15PM).

**Síntoma**: detector `G-NEW-IAM-NAMING-FULL` flaggearía como FAIL los nombres exactos ADEA actuales:
- `ACME-R-ADEA-WEBAPP-ADMIN`
- `ACME-R-ADEA-RESOURCE-ACCESS`

Mi regex actual `^ACME-R-{App}-{A|DES|SL}$` no admite sufijos `WEBAPP-ADMIN` ni `RESOURCE-ACCESS`.

**Fix v3.8.1**:
- Añadir lista `iam_role_naming.exceptions` en `aios/governance/rules/naming.yaml` con prefijos reservados (`ADEA`, `WEBAPP`, etc.).
- Actualizar `NamingChecker._check_iam_naming()` para skip si token coincide con exception.
- Test: assert `ACME-R-ADEA-WEBAPP-ADMIN` NO produce finding.

**Esfuerzo**: ~30min · 1 commit + test.

### G-DRIFT-2 · log-retention threshold ≥90d · LOW · alineación f03

**Origen**: `BO-ACME/CS_Scripts@compliance/check_f03_compliance.py:447` exige `retentionInDays >= 90`.

**Status v3.8.0**: Sugerencia del detector `ACME-CDK-LAMBDA-NO-LOG-RETENTION` actualizada a `RetentionDays.THREE_MONTHS` (90d) · ✅ ya alineado con commit del sprint v3.8.0.

**Pendiente v3.8.1**: añadir un detector secundario que flague Lambdas con `log_retention=RetentionDays.ONE_MONTH` (30d) explícitamente como WARN ("log retention < 90d · ACME exige 90d hot tier").

### G-DRIFT-3 · _iter_files() no soporta prefijos en globs · LOW

**Origen**: descubierto durante F3 testing del sprint v3.8.0 (`tests/test_governance_naming_checker.py`).

**Síntoma**: `FILE_GLOBS["cmk"]` incluye `**/cdk*.py` pero `_iter_files()` solo extrae sufijos `**/*.ext`. Resultado: archivos `cdk_stack.py` con aliases custom NO son escaneados por detectores `G-NEW-CMK-NAMING` ni `G-CDK-KMS-AWS-MANAGED-PROHIBITION` desde código Python.

**Workaround**: scan vía `.tf`/`.ts` files (que sí matchean por sufijo).

**Fix v3.8.1**: refactorizar `_iter_files()` para soportar `fnmatch` sobre nombres de archivo además de sufijos. Esfuerzo ~1h · revisar tests existentes.

### Pre-publish v3.8.0 audit context

Audit ejecutado 29-abr-2026 17:50 sobre 4 repos BO-ACME ancla:

| Repo | Última commit relevante | Status |
|---|---|---|
| `amazon-q-rules` | 4 meses atrás (PR #15) | ✅ sin cambios |
| `devops-kiro-gov` | 2026-04-28 (v0.1.6 · rule_update PR #9) | ✅ sólo update spec dynamic-lambda-dashboard · no afecta governance |
| `CS_Scripts` | 2026-04-29 12:15PM (v0.12.0) | ⚠ 3 drift items (ver G-DRIFT-1/2/3) |
| `CS_CI_Artifacts` | 2026-04-29 (v2.26.0) | ✅ buildspec patterns sin cambio relevante |

**Conclusión**: v3.8.0 sale con G-DRIFT-2 ya corregido en flight · G-DRIFT-1 y G-DRIFT-3 documentados para v3.8.1.
