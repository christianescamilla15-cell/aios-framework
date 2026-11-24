# Paquete de gobierno · guía operativa

El paquete de gobierno convierte las reglas de una organización (clasificación por TIER, convenciones de
nombres, cadena de firmas y destinatarios de escalamiento) en **datos** (`aios/governance/rules/*.yaml`)
que la CLI valida y usa para generar solicitudes.

> Los YAML del repositorio describen a **Acme Corp, una organización ficticia**: 8 aplicaciones
> inventadas, roles con buzones `@acme.example` (dominio reservado) y cifras de ejemplo. Para usarlo en
> una organización real, reemplaza los cuatro YAML manteniendo las mismas llaves.

## 1 · Comandos

```bash
aios tier classify --app partners --explain          # 9 criterios + incoherencias del TIER declarado
aios governance check --app billing --root .         # TIER + nombres + estado de firmas
aios governance request --type bd-access --app billing --format md
aios governance audit --app billing                  # tabla de solicitudes y su estado
aios governance audit --app billing --update --request-id <ID> --status in-review --signer pmo@acme.example
aios governance escalate --app billing --auto        # escala lo detenido según los umbrales
```

Tipos de solicitud (`--type`): `bd-access`, `aws-account`, `aws-account-dedicated`, `aws-account-shared`,
`cmk-request`, `hardware-key`, `mailing-list`.

## 2 · Reglas de TIER (`tiers.yaml`)

| Regla | Qué detecta |
|---|---|
| `TIER_T3_FORBIDS_PII` | App declarada T3 cuyo expediente dice «PII Sí» → se sugiere T2 |
| `TIER_T0_T1_NO_SHARED_ACCOUNT` | App T0/T1 listada en una cuenta compartida |
| `TIER_T0_REQUIRES_MULTIREGION` | App T0 sin activo-activo en dos regiones (expediente o CDK) |
| `TIER_T0_RTO_BIA` | RTO del BIA mayor que `tiers.T0.rto_minutes` |
| `TIER_T3_RETIREMENT` | App T3 marcada como permanente (T3 implica retiro) |
| `TIER_RECLASSIFICATION_PENDING` | `tier_status` en revisión o promovido (informativo) |

## 3 · Bitácora de firmas (`audit_trail.py`)

Cada cambio de estado se agrega a `.aios/governance/audit-trail.jsonl` con el SHA-256 de la entrada
anterior; `verify_chain()` detecta cualquier edición. Máquina de estados:

```
draft → requested → in-review → partially-approved → approved → provisioned ⇄ renewed
             ↘ rejected / cancelled          ↘ expired → renewed        ↘ revoked
```

`rejected`, `cancelled` y `revoked` son terminales. Cualquier otra transición se rechaza.

## 4 · Escalamiento (`approvals.yaml · slippage_thresholds`)

| Días sin avance | Severidad | Destinatario por omisión (`escalation_targets`) |
|---|---|---|
| ≥ `warn_after_days` (3) | `warn` | Oficina de Proyectos |
| ≥ `escalate_after_days` (5) | `escalate` | Patrocinador del programa |
| ≥ `emergency_after_days` (10) | `emergency` | Comité directivo |

`--to <key>` elige cualquier destinatario de `escalation_targets` o `manual_targets`.

## 5 · Códigos de salida

| Comando | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| `governance check` | pasa | WARN con `--strict` | hallazgo FAIL, app desconocida o raíz inválida | hallazgo CRITICAL |
| `governance request` | solicitud generada | tipo de recurso inválido | app fuera de alcance | — |
| `governance audit --update` | transición registrada | transición inválida o faltan `--status`/`--signer` | app o solicitud inexistente | cadena de la bitácora corrupta |
| `governance escalate` | escalamiento enviado | nada que escalar | destinatario `--to` inválido | error inesperado |
| `release` | listo | no listo (compuerta) | — | — |
