# AIOS Governance Pack · Guía operativa eTribe

**Versión:** v3.8.0 · 2026-04-29
**Audiencia:** equipo eTribe (Christian · Oscar · Alonso · Gustavo · Víctor) y Borde Arq
**Alcance:** programa Finance Operations Modernization 2026 · 8 aplicativos ACME

---

## 1 · Qué es el Governance Pack

5 subcomandos del CLI `aios` que automatizan los flujos de gobernanza ACME descritos en sesiones 23-abr a 28-abr 2026:

| Subcomando | Propósito | Implementación |
|---|---|---|
| `aios governance check` | Valida reglas ACME (TIER · naming · approvals · stakeholders) sobre el repo del aplicativo | F2 Día 3 |
| `aios governance request` | Genera Markdown + PDF formal de solicitud (BD · AWS · CMK · YubiKey · DL) + entry inicial al audit trail | F2 Día 4 |
| `aios governance audit` | Audit trail SHA256-chained con 11 estados (state machine), detección de tampering, slippage tracking | F2 Día 5 |
| `aios governance escalate` | Detecta firmas atoradas (>3/5/10d) y genera correo de escalación con auto-routing al destinatario apropiado | F2 Día 6 |
| `aios tier classify` | Clasifica un aplicativo aplicando los 9 criterios oficiales ACME · detecta mismatches (ej: caso SRG declared T3 + PII Sí) | F2 Día 7 |

---

## 2 · Flujo end-to-end · ejemplo FLEET_OPS_APP

### 2.1 · Generar solicitud BD legacy

```bash
cd /path/to/01-fleet_ops_app
aios governance request \
    --type bd-access \
    --app fleet_ops_app \
    --output ./governance-requests/ \
    --requester engineer@acmeair.com
```

Esto produce:
- `governance-requests/GOV-FLEET_OPS_APP-BD-20260429-001.md` (Markdown · listo para revisar)
- `governance-requests/GOV-FLEET_OPS_APP-BD-20260429-001.pdf` (PDF formal · listo para enviar por correo)
- `.aios/governance/audit-trail.jsonl` (entry inicial · estado `requested`)

### 2.2 · Trackear firmas conforme avanzan

```bash
# Luis Ertuche (PM) firma · estado pasa a 'in-review'
aios governance audit \
    --app fleet_ops_app \
    --update \
    --status in-review \
    --signer "Luis Ertuche" \
    --actor-role pm \
    --notes "Validado contexto · OK"

# DBA custodio firma · estado pasa a 'partially-approved'
aios governance audit \
    --app fleet_ops_app \
    --update \
    --status partially-approved \
    --signer "DBA Miatech" \
    --actor-role dba

# CYBER firma · sigue 'partially-approved' (avanza un paso de la cadena)
# ... etc hasta 'approved' por sponsor
```

Cada call:
- Valida la transición (state machine 11 estados · transitions inválidas son rechazadas con error claro)
- Calcula SHA256 del entry + chain con prev_hash (tamper-evident)
- Persiste como JSONL append-only

### 2.3 · Detectar slippage y escalar automáticamente

Cron diario (o manual) corre:

```bash
aios governance escalate --app fleet_ops_app --auto
```

Si alguna firma lleva >3 días sin avanzar:
- `severity=warn` (3-5d) → routing a Luis Ertuche
- `severity=escalate` (5-10d) → routing a Elías Tapia (sponsor único)
- `severity=emergency` (>10d) → routing a sponsor business (Víctor Araiza · Eloisa · J.T.)

Genera Markdown + PDF + nuevo entry `escalation_sent` en el audit trail (loop cerrado · todo trazable SOX).

### 2.4 · Validar reglas continuamente

```bash
aios governance check --app fleet_ops_app --root .
```

Detecta:
- Naming violations (IAM · CMK · Secret · KMS-AWS-managed prohibition)
- TIER mismatches (caso SRG · caso Robot multi-region missing)
- Slippage en audit trail (warn/escalate/emergency)

---

## 3 · 9 criterios oficiales ACME (referencia)

`aios tier classify --app <name> --explain` muestra los 9 criterios evaluados:

| # | Criterio | Origen YAML | Inferencia |
|---|---|---|---|
| 1 | Impacto ingresos | `tiers.yaml.assignments[app].rationale` | Heurística: "alto/medio/bajo/muy_bajo impacto" en texto |
| 2 | Impacto servicio | idem | mismo regex |
| 3 | Impacto operación | idem | mismo regex |
| 4 | **PCI / PII** (KEY · descalifica T3) | `rationale` + `pci_dss_scope` | "PII Sí" / "PCI Sí" / `pci_dss_scope: true` |
| 5 | Vigencia (permanente vs decomiso 18m) | `rationale` | "decomiso" → vigencia=False |
| 6 | HA / Continuidad | `rationale` | "Activo-Activo multi-región" / "Activo-Pasivo" / "multizona" |
| 7 | Disponibilidad target | `tiers.yaml.tiers[T0..T3].disponibilidad` | Estructurado |
| 8 | RTO / RPO (min) | `rationale` regex `RTO Xm` | Extraído |
| 9 | Estrategia migración | `rationale` | "refactoring" / "replatform" / "relocate" / "decomiso" |

5 reglas de validación oficiales (`tiers.yaml.validation_rules`):
- `TIER_T3_FORBIDS_PII` (HIGH) · caso SRG: T3 + PII Sí → debe ser T2 mínimo
- `TIER_T0_T1_NO_SHARED_ACCOUNT` (HIGH) · cuenta dedicada obligatoria
- `TIER_T0_REQUIRES_MULTIREGION` (HIGH) · Activo-Activo Virginia + Oregon (ADR-002 v2)
- `TIER_T0_RTO_15MIN_BIA` (HIGH) · RTO ≤10-15min para T0
- `TIER_T3_DECOMISO_18MONTHS` (LOW) · T3 implica decomiso ≤18m

---

## 4 · State machine · 11 estados (audit trail)

```
draft → requested → in-review → partially-approved → approved → provisioned → renewed
                          ↓                               ↓
                       rejected                      cancelled / revoked / expired
```

Reglas:
- `draft` y `requested` son los únicos estados permitidos como inicial (desde `None`)
- `approved` no puede regresar a `requested` (transición rechazada)
- `provisioned` es estado terminal del flow exitoso (excepto `renewed` cíclico)

Validación en código: `audit_trail.is_valid_transition()` consulta `VALID_TRANSITIONS` dict.

---

## 5 · Auto-routing escalation (referencia)

Defaults en `approvals.yaml.slippage_thresholds`:

| Severity | Días sin avance | Destinatario default | Override flag |
|---|---|---|---|
| warn | 3-5 | Luis Ertuche · `luisertuche@acmeair.com` | `--to luis` |
| escalate | 5-10 | Elías Tapia · `etapia@acmeair.com` | `--to elias` |
| emergency | >10 | Víctor Araiza · Eloisa · J.T. · `varaiza@acmeair.com` | `--to sponsor` |

Override manual disponible: `--to luis | elias | sponsor | victor | miguel-rachid | auto`.

Cron-friendly: `--auto` o `--json` produce output JSON estable para integración con scheduled triggers.

---

## 6 · Configuración por aplicativo (YAML)

Los 4 archivos canónicos en `aios/governance/rules/`:

| YAML | Líneas | Contenido |
|---|---|---|
| `tiers.yaml` | 466 | 4 TIERs con 9 criterios + 8 reglas validación + 8 assignments |
| `approvals.yaml` | 393 | Cadena 5 firmas + 11 chains by resource type + state machine + slippage thresholds |
| `naming.yaml` | 353 | 5 naming patterns con regex + 8 AppPrefixes |
| `stakeholders.yaml` | 494 | 5 eTribe + 30 ACME stakeholders + matriz contactos |

Editar estos YAMLs y re-correr `aios governance check`/`aios tier classify` para validar.

---

## 7 · Recetas comunes

### 7.1 · Onboarding nuevo aplicativo (post v3.8.0)

```bash
# 1. Editar tiers.yaml.assignments[<new_app>] con rationale
# 2. Validar
aios tier classify --app <new_app> --explain

# 3. Si TIER OK · generar primera solicitud BD
aios governance request --type bd-access --app <new_app>

# 4. Trackear avance
aios governance audit --app <new_app>
```

### 7.2 · Demo a stakeholders ACME

```bash
# 30 segundos · audit + check + tier classify de FLEET_OPS_APP
aios governance audit --app fleet_ops_app
aios governance check --app fleet_ops_app --strict
aios tier classify --app all
```

### 7.3 · Cron diario (sugerido)

```cron
# Cada día a las 09:00 · escala todos los slippages cross-app
0 9 * * 1-5  cd /path/to/repo && aios governance escalate --app all --auto >> /var/log/aios-escalations.jsonl
```

---

## 8 · Cambios recientes

**v3.8.2 (29-abr noche)** · CFDIs marcado `out_of_scope_29abr` (decisión LJ) · scope vigente 7 apps · `supported_apps` filtra automáticamente · `all_apps` preserva catálogo histórico · G-DRIFT-1 cerrado (ADEA naming exceptions) · G-DRIFT-3 cerrado (`_iter_files` con fnmatch).

**v3.8.1 (29-abr tarde)** · brand rename eTride → eTribe (consultora con B).

**v3.8.0 (29-abr)** · release inicial Governance Pack.

Drifts pendientes: ninguno material. Ver `BACKLOG.md` para items futuros.

---

## 9 · Soporte

- Slack canal eTribe (TBD)
- Issues en `acme-team/aios-framework` (privado)
- Owner: Christian Hernández Escamilla · `engineer@acmeair.com`
