# ADR-AIOS-005 · Governance Pack v3.8.0

**Status:** Accepted (release 2026-04-29)
**Date:** 2026-04-28 · finalized 2026-04-29
**Authors:** Christian Hernández Escamilla (eTribe · Líder técnico programa)
**Reviewers (pending):** [n/a · ADRs internos AIOS sin firma externa requerida]
**Supersedes:** N/A (módulo nuevo)
**Related:** ADR-002 v2 (compute FLEET_OPS_APP) · ADR-003 (secrets) · ADR-004 (persistence) · Sprint Plan v3.8.0

---

## 1. Context

A lo largo de las primeras 8 sesiones del programa Finance Operations Modernization (06-abr a 28-abr 2026), el equipo eTribe ha consolidado un knowledge base implícito sobre **governance ACME**: tabla TIER oficial, 5 firmas en cadena, naming patterns IAM/Repo/CMK/Secret, custodia DxC/Miatech/ACME TI, validadores Roberto Carlos + José Ángel León, etc.

Este conocimiento hoy reside en:
- Documentos PDF aislados (Caso de Uso FLEET_OPS_APP BD · Speech TIER · Plan Admin Week 1)
- Memorias del agente
- Cabezas del equipo (Christian · Alonso · Oscar · Gustavo · Víctor)
- Transcripciones sueltas

**Problema identificado:** cada vez que se necesita pedir un acceso/recurso (cuenta AWS · CMK · YubiKey · BD legacy), se redacta manualmente un PDF formal. Para FLEET_OPS_APP ya tenemos 6+ correos-tipo. Para los **otros 7 aplicativos** del programa (Robot · BSP · ARC · CFDIs · SRG · ASR · NoShow), replicar el mismo manual labor implica ~50 horas adicionales de redacción + audit trail.

Adicionalmente, hoy NO existe un mecanismo automatizado para:
- Validar que un aplicativo cumple las reglas TIER oficiales (caso SRG: T3 declarado pero PII Sí · descalificación automática)
- Auditar quién firmó qué cuando (audit trail SOX-friendly)
- Detectar slippage de firmas (>5 días sin avance · bloquea cronograma)
- Generar correos de escalación con bloqueadores listados

## 2. Decision

Implementar el módulo **`aios.governance`** dentro del framework AIOS v3.8.0 que:

### 2.1 Catálogo de reglas en YAML (entregado · Día 1)

Los 4 archivos `aios/governance/rules/*.yaml` contienen el knowledge base completo:

- `tiers.yaml` · 4 TIERs · 9 criterios · 8 reglas validación · asignación 8 apps · modelo 18 cuentas
- `approvals.yaml` · 5 firmas · 11 cadenas por recurso · state machine 11 estados
- `naming.yaml` · 5 detectores nuevos con regex (IAM · Repo · CMK · Secret · Branch)
- `stakeholders.yaml` · 5 personas eTribe + 30 personas ACME · matriz de contacto

### 2.2 Subcomandos CLI nuevos (Días 3-7)

```
aios governance check     --app <app>             # Valida reglas ACME
aios governance request   --type <type> --app ... # Genera PDF formal
aios governance audit     --app <app> [--update]  # Audit trail 5 firmas
aios governance escalate  --app <app> --to <who>  # Escalación slippage
aios tier classify        --app <app> [--explain] # Clasificación TIER
```

### 2.3 Detectores nuevos (Día 7)

10 detectores nuevos · agregan a los 36 existentes en v3.7.5 → 46 totales en v3.8.0:

- `G-NEW-IAM-NAMING-FULL` · `ACME-R-{App}-{A/DES/SL}` regex
- `G-NEW-REPO-NAMING` · `RevAcc_{App}{Tipo}` convención
- `G-NEW-CMK-NAMING` · `acme-kms-{app}-{scope}`
- `G-NEW-SECRET-NAMING` · `acme/{##-app}/{type}`
- `G-NEW-BRANCH-PROTECT` · `feature/etriber` working master
- `G-NEW-TIER-PII-MISMATCH` · caso SRG (T3 con PII)
- `G-NEW-TIER-MULTIREGION-MISSING` · T0/T1 sin Aurora Global
- `G-NEW-TIER-PITR-MISSING` · T0/T1 sin Continuous backup
- `G-NEW-TIER-BIA-MISMATCH` · BIA declarado vs criterio TIER
- `G-NEW-TIER-DEDICATED-ACCOUNT` · T0/T1 NO comparten cuenta

### 2.4 Persistencia audit trail (Día 5)

`.aios/governance/audit-trail.jsonl` · append-only · SHA256 chained.

Cada solicitud genera entries inmutables con:
- entry_id · request_id · timestamp
- state_from → state_to (state machine 11 estados)
- actor + actor_role
- prev_hash + entry_hash (SHA256 chain · tamper-evident)

### 2.5 Templates Jinja2 (Día 4)

5 templates iniciales en `aios/governance/templates/`:
- `bd-access.j2` (basado en Caso_Uso_SICOFAV_BD existente)
- `aws-account.j2` (basado en email-tipo Plan Admin Week 1)
- `cmk-request.j2` (umbrella ticket GateOne)
- `yubikey-request.j2` (CYBER form)
- `dl-inclusion.j2` (correo a Solution Architects)

## 3. Alternatives considered

### Alt 1 · Mantener manual labor (status quo)
- ❌ NO escalable a 8 apps × 6 tipos de solicitudes = 48 PDFs manuales
- ❌ Sin audit trail formal · auditoría SOX más difícil
- ❌ Knowledge base disperso · alto riesgo de bus-factor

### Alt 2 · Wiki/Confluence con templates
- ❌ NO ejecutable como código · no valida CDK/IaC en tiempo real
- ❌ Sin integración con detectores AIOS existentes
- ❌ No tamper-evident audit log

### Alt 3 · Servicio externo (Jira workflow custom · ServiceNow)
- ❌ Requiere licencias adicionales · setup complejo
- ❌ Acoplamiento con sistemas ACME que tardan en aprobarse
- ❌ NO portable a otros programas (ej. si AIOS se usa fuera de Finance Operations)

### Alt 4 (elegida) · Módulo nativo AIOS · YAMLs + CLI + Jinja2
- ✅ Self-contained · sin dependencias externas
- ✅ Integrable con detectores existentes (mismo framework)
- ✅ Portable · cualquier programa ACME puede adoptarlo
- ✅ Audit trail jsonl tamper-evident · SOX-friendly
- ✅ Templates en Jinja2 · industria estándar · weasyprint para PDF
- ✅ Knowledge base en YAML · editable sin redeploy

## 4. Consequences

### Positive

- **Reduce 50%+ del manual labor administrativo del equipo eTribe**: las 6 horas/semana en redactar correos + PDFs + tracking firmas pasa a "1 comando + verificación"
- **Audit trail SOX-friendly**: las firmas en cadena quedan registradas inmutables · cualquier auditor externo puede pedir el jsonl como evidencia
- **Escalable a las 8 apps del programa**: cambia el `--app` y el resto se adapta vía templates
- **Demostrable a Elías + Borde Arq**: en sesión 30 min se muestra "antes vs después" como ROI técnico del programa
- **Captura learnings T1-T8 FLEET_OPS_APP**: el patrón meta-regresión composition root + reglas de governance quedan en código · no en cabezas
- **Naming gates en pre-commit**: 5 detectores fallan rápido si alguien usa `acme-r-fleet_ops_app-A` (lowercase) o `RevAcc_Sicofav_Backend` (underscore)
- **Reusabilidad cross-programa**: si ACME adopta AIOS para otros programas (Pagos · Loyalty · etc.), el módulo `governance` se exporta byte-exacto · solo cambian los YAMLs

### Negative

- **Bus factor sigue siendo Christian** durante v3.8.0: la implementación 100% recae en el lead técnico · 12 días de trabajo
- **Mantenimiento de los YAMLs**: si ACME cambia las reglas TIER (Tiers 2.xlsx), hay que actualizar `tiers.yaml` · proceso manual hasta que tengamos integración API con Domini's catalog
- **Templates Jinja2 frágiles a cambios de formato**: si ACME exige nuevo formato corporativo para correos, hay que re-tunear los 5 templates
- **No reemplaza la negociación humana**: las firmas siguen requiriendo a las personas reales · AIOS solo automatiza la generación + tracking
- **Riesgo de "false sense of compliance"**: pasar `aios governance check` ≠ pasar CYBER · el chequeo es necesario pero no suficiente

### Neutral / TBD

- Adopción del equipo eTribe: depende de la documentación + onboarding · planeado en Día 11 (`GOVERNANCE_GUIDE.md`)
- Aceptación por ACME: si Borde Arq + Elías firman valor en demo (Día 12 · 14-may), se promueve como standard interno
- Relación con `aios discovery-generate`: actualmente independientes · futuro v3.9.0 puede consolidarse

## 5. Implementation plan (resumen)

Detalle completo en `Sprint_Plan_AIOS_v3.8.0_Governance_Pack_28abr.pdf` (4 páginas):

| Fase | Días | Output |
|---|---|---|
| F1 · Discovery & Design | 1-2 (29-30 abr) | 4 YAMLs + 4 skeletons + ADR-AIOS-005 (este doc) |
| F2 · Core Implementation | 3-7 (01-07 may) | 5 subcomandos + 10 detectores |
| F3 · Testing & Integration | 8-10 (08-12 may) | ~50 tests · smoke E2E FLEET_OPS_APP · 0 regresiones |
| F4 · Documentation & Release | 11-12 (13-14 may) | Tag v3.8.0 · push · email · demo Elías |

**Día 1 ya cerrado · adelanto de ~1 día del cronograma original.**

## 6. Cross-references · sources

### Internal AIOS docs

- Sprint_Plan_AIOS_v3.8.0_Governance_Pack_28abr.pdf (4 páginas · 33 subtareas)
- aios/governance/rules/tiers.yaml (466 líneas)
- aios/governance/rules/approvals.yaml (393 líneas)
- aios/governance/rules/naming.yaml (353 líneas)
- aios/governance/rules/stakeholders.yaml (494 líneas)
- aios/cli/governance.py (skeleton · F2 Día 3+)
- aios/governance/tier_classifier.py (skeleton · F2 Día 7)
- aios/governance/audit_trail.py (skeleton · F2 Día 5)
- aios/governance/templates/{bd-access · aws-account · cmk-request · yubikey-request · dl-inclusion}.j2

### External · ACME governance sources

- **Tiers 2.xlsx · sheet Tier_definicion** · catálogo TIER oficial · equipo Domini
- **Sesión Solution Architects ACME** · 27-abr-2026 03:30 PM (Fernando Pérez Izquierdo + Rigo Ferqui + Luis Ertuche + Christian Hernández + Juan Carlos Vázquez Lorenzo + Gerardo Téllez Pacheco)
- **Imagen oficial 3 perfiles IAM ACME** · 28-abr-2026 (Administrador FullAccess + Desarrollador Power User + Consultor/Soporte Read Only)
- **Plan Maestro General v6 · Plan B** · 25-abr-2026 (4 fases por aplicativo · 51 actividades padre · 244 subtareas)
- **Caso de Uso FLEET_OPS_APP BD** · 28-abr-2026 (template formal · 5 firmas en cadena documentadas)
- **Sprint Plan AIOS v3.8.0** · 28-abr-2026 (33 subtareas · 4 fases · cronograma 12 días)

### Memories triggers

- project_amx_accesos_tier_28abr.md (junta accesos × TIER · equipo eTribe oficial · 18 cuentas AWS plan)
- project_aios_v380_sprint_d1_28abr.md (este sprint · F1 Día 1 cerrado)
- project_sicofav_triangulation6_27abr.md (patrón meta-regresión cementado tras 8 sesiones)
- project_amx_10apps_clones_consolidados_27abr.md (post scope-change · 8 apps confirmadas)
- reference_amx_governance_systems.md (Optimo · LeanIX · ServiceNow · 3 sistemas distintos)

## 7. Decision · authorization

**Esta ADR queda en estado `Proposed`** · sin firma externa requerida (es interna del framework AIOS).

Christian Hernández Escamilla (autor + lead técnico) autoriza arranque del sprint.

Para futuras revisiones · se sugiere comentarios de:
- Equipo eTribe (Oscar · Alonso · Gustavo · Víctor) · validación práctica
- Borde Arquitectura (Israel Miguel González Sandoval) · si se promueve a estándar ACME
- Elías Tapia (sponsor único interno ACME) · post-demo Día 12 (14-may-2026)

---

**ADR Status:** Accepted
**Sprint:** AIOS v3.8.0 Governance Pack
**Target Release:** 2026-05-12 → 2026-05-14 · **Actual: 2026-04-29 (~13 días adelantado)**
**Branch:** `feat/v3.8.0-governance-pack`

---

## Outcome · Sprint cerrado 2026-04-29

| Fase | Día planeado | Día real | Status |
|---|---|---|---|
| F1 · Diseño + 4 YAMLs base | 28-abr | 28-abr | ✅ |
| F2 Día 3 · governance check | 01-may | 28-abr | ✅ |
| F2 Día 4 · governance request | 02-may | 28-abr | ✅ |
| F2 Día 5 · governance audit | 03-may | 28-abr | ✅ |
| F2 Día 6 · governance escalate | 06-may | 29-abr | ✅ |
| F2 Día 7 · tier classify | 07-may | 29-abr | ✅ |
| F3 · Testing & Integration | 12-may | 29-abr | ✅ 75 tests · 503 suite total · 0 regresiones |
| F4 · Docs + Release | 14-may | 29-abr | ✅ |

**Drift items pre-release** (ver BACKLOG.md):
- G-DRIFT-1 ADEA naming exception (v3.8.1)
- G-DRIFT-2 log-retention 90d (corregido in-flight)
- G-DRIFT-3 _iter_files glob prefix support (v3.8.1)
