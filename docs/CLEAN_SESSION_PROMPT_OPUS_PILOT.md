# Clean-session prompt · AIOS v3.0.0 Opus-powered pilot

Este prompt es **self-contained**. Copia-y-pega a sesión limpia (Claude Code o claude.ai web con Opus 4.7 activo · Max Pro cubre esto). NO menciones al agente que sesiones previas existen.

---

## Prompt

```
Eres un security auditor senior revisando código .NET legacy decompilado. Framework usado: AIOS v3.0.0 (aios-framework · github.com/christianescamilla15-cell/aios-framework) · detectores estáticos regex + ontología de dominio AMX + característerización de API.

**Target**: `ATOS-NOSHOW-ROBOT` · código C# .NET Framework 4.7.2 · revenue accounting Aeroméxico · 29 archivos · decompilación del binario productivo (Néstor/Richard reversaron el .exe porque ATOS no dejó el source).

Este es un sistema crítico: procesa reportes diarios de no-shows, envía a SFTP CADUCOS, emails internos, consume SABRE SOAP. BD AIDX migrada a AWS el 2026-04-21.

**Tu tarea**: doble modo.

### Modo 1 · Classification Opus de findings del scanner (21 pending)

Dado el output de `aios review list --format json` (21 findings), para cada uno:
1. Lee el archivo en `ATOS-NOSHOW-ROBOT/<file>` en contexto ±20 líneas
2. Razona paso a paso: ¿qué CWE aplica · qué intent muestra el código · es bug/business_rule/migration_candidate/unclear?
3. Emite JSON con: `{finding_id, classification, confidence, reasoning (1-2 oraciones), evidence (3 bullets), recommended_action}`

Factors a considerar (few-shot):
- Credencial plaintext en App.config · **bug** · CWE-798
- Flight number hardcoded con evidencia git blame "manual patch ops" · **business_rule**
- Singleton sin thread-safety en integration adapter · **bug** salvo que haya comment documentando intentional single-threaded
- Generic catch con log + return · si oculta root cause · **bug**; si es wrapper resilience para retry · **migration_candidate** (fix_template: Polly)

### Modo 2 · Deep review beyond scanner

Lee estos 5 archivos completos:
- `Business/MainServices.cs` (el orchestrator)
- `Business/Adapter/SabreAdapter.cs` (SOAP client con singleton + retry)
- `Business/Adapter/SFTPAdapter.cs` (upload SFTP)
- `Business/Adapter/EmailAdapter.cs` (email notification)
- `Business/BO/SabreBO.cs` (business logic SABRE)

Busca issues que el scanner estático (regex-based) NO detectaría pero un auditor humano senior SÍ vería:
- Logs con PII plaintext (passengerName · PNR · ticketNumber) · CWE-532 · CWE-312
- Logs con credenciales / tokens · CWE-532
- Catches vacíos o que `throw ex` vs `throw` · CWE-755
- Recursión sin max depth · CWE-674
- Race conditions en lazy init singletons · CWE-362
- Missing host key verification (SFTP/SSL) · CWE-295
- Passwords en memoria como `string` vs `SecureString` · CWE-316
- Hardcoded recipients en exception handlers · CWE-798 variant
- Error swallowing masking root cause · CWE-391
- Design smells: nesting > 5 · magic strings · configs leídas en class init

Reporta como: `{id: DR-NN, file, line, severity, cwe, message (3-5 líneas con evidencia)}`.

### Output final esperado

Entrégame:

**A. Tabla classification** · 21 filas · `finding_id · classification · confidence · 1-line reasoning`
**B. Tabla deep review** · N filas · `DR-id · file:line · severity · cwe · message`
**C. Coverage vs audit humano 25 findings** · mapeo ID-humano → detector (A/B/C/D) · qué % cubierto
**D. 3 hallazgos más impactantes** · tu ranking personal · con una línea de por qué son críticos post-refactor

### Context files que necesitas

- `ATOS-NOSHOW-ROBOT/` repo completo
- `amx-hallazgos-audit/apps/10-noshow/Analisis_NoShow_para_sesion_23abr.md` · los 25 findings humanos como gold standard
- `aios-framework/aios/policies/amx-revenue-accounting/ontology.yaml` · 26 patterns AMX

### Constraints

- **No overselling**. Si hay 12% de hallazgos irreductibles (compliance regulatoria · arquitectural · product decisions) · dilo explícito.
- **No synthetic gold**. El baseline son los 25 findings del audit humano del 23-abr. Frankenstein y sus 79 SEED son tautológicos · ignóralos para esta medición.
- Confidence < 0.5 · devuelve `unclear` · pause_for_review.
- Si no puedes abrir un archivo · di "file not accessible" en el reasoning.

---

## Checkpoint de honestidad

Antes de emitir el reporte final, responde (1 línea cada una):
- ¿Cuál es tu coverage medida (A findings del humano cubiertos) sobre 25?
- ¿Agregaste cuántos Deep Review findings que el humano NO listó?
- ¿Hay findings del humano que NO pudiste confirmar desde el código? Nombra cuáles.

Publica tu análisis con evidencia · evita frases marketing · prioriza números medidos vs proyectados.
```

---

## Para ejecutar este prompt en sesión limpia

1. Abre Claude Code fresh session (o claude.ai web con Opus 4.7)
2. Asegúrate de tener acceso a los 3 workspaces:
   - `/mnt/c/Users/eTriber/Downloads/ATOS-NOSHOW-ROBOT/`
   - `/mnt/c/Users/eTriber/Desktop/amx-hallazgos-audit/apps/10-noshow/`
   - `/mnt/c/Users/eTriber/Temp/aios-framework/`
3. Pega el prompt completo arriba (todo entre ```)
4. El agente debería tomar ~15-30 min · razonando sobre los archivos + cross-referenciando con los 25 findings humanos
5. Compara el output con los números reportados por esta sesión (v3.0.0) · cualquier divergencia es señal útil:
   - Menos cobertura → sobre-estimé · corrijo en siguiente iteración
   - Más cobertura → la sesión limpia ve cosas que yo no ví

## Validación cruzada · qué comparar

Métrica	Sesión actual (esta conversación)	Sesión limpia (Opus fresh)	Delta
Coverage 25 humanos	22/25 = 88%	?	?
Deep review adicionales	14	?	?
Findings auto-confirmados	—	—	—
Classifications bug/br/mc/uc	9/6/3/3	?	?

Si el delta es >10% · la sesión con contexto (esta) está sesgada. Si es <5% · el framework + Opus converge a un número defendible.
