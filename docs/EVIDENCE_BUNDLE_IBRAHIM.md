# Evidence Bundle · AIOS v1.7.4 + Power `amx-aios-unified`

**Destinatario:** Alberto Ibrahim Pedraza Cáscar · Tech Lead AM-KIRO · Aeroméxico
**Autor:** Christian Hernández Escamilla · eTrive
**Fecha:** 2026-04-22
**Objetivo:** solicitar acceso OYN-AMX y proponer contribución del pack AIOS al framework AM-KIRO

---

## TL;DR

Construí `amx-aios-unified` · un Kiro Power que empaqueta **4 sistemas** (AIOS spec-driven + Mythos scanner + Arena self-play + Nemesis engagement) en una sola unidad instalable. Lo validé end-to-end sobre un workload sintético realista de **70,265 LoC en 6 lenguajes** · el refactor completó en **2h 49min wall-clock** · entregó **release_gate READY · pre-deploy completo** (CI/CD · Docker · K8s · Helm · Terraform · observability · SLOs · chaos · load tests · ADRs).

El pack + el framework AIOS están **drop-in compatibles** con tu arquitectura AM-KIRO (manifest.json · .kiro/ · packs system). Propongo contribuirlo como `aios` pack oficial.

### Honestidad metodológica sobre el alcance

Al validarlo contra un análisis humano experto real sobre NoShow, el framework captó **7 de 28 hallazgos (25% de recall)** · los 21 restantes son **bugs de dominio** (vuelo 829 hardcoded · drift entre configs · secretos en test.config · código marcado para eliminación · anti-patrones de negocio) que los 72 detectores CWE de Mythos **no cubren por diseño**.

**El framework no sustituye un análisis humano experto** · lo complementa. Vale la pena cuando:
- Das baseline mínimo en segundos sobre un codebase sin análisis previo
- Necesitas evidencia automatizada reproducible para los 4 gates AMX (WIZ/Veracode/Prisma/Tenable)
- Escalas a N apps donde hacer análisis humano profundo a cada una toma semanas
- Funcionas como red de seguridad sobre CWE estándar que el humano pudo olvidar

No vale como narrativa única cuando ya hay Resumen Técnico humano · el aporte marginal es bajo.

---

## 1 · Qué construí y por qué importa para AMX

### El problema

El audit del 20-abr (que presentaste con las 46 vulnerabilidades clasificadas del scope revenue-accounting) identificó que:

1. **Cada app tiene refactor pendiente** con CWEs específicos · 26 CRITICAL + 16 HIGH distribuidos en 10 módulos
2. **No hay playbook repetible** · cada equipo resuelve a mano cada FRK sin spec formal
3. **Compliance post-retro 20-abr** (sin ECS · sin SES/SNS · KMS · Akamai · correlation-id · amx-r-*) · no automatizado
4. **Evidencia de pre-deploy** (WIZ · Veracode · Prisma · Tenable · approval Miguel Rachid) · manual cada vez

### La solución · AIOS como framework

AIOS es un **framework AI-engineering** que convierte todo esto en un pipeline determinista:

```
Spec-driven (EARS requirements → design → tasks)
    ↓
Refactor con build-gates obligatorios por lenguaje
    ↓
Regression tests por FRK
    ↓
Security scan (Mythos · 72 detectores · 21/28 CWEs · 9 lenguajes)
    ↓
CI/CD workflows (15 GitHub Actions · multi-stack)
    ↓
Deployment artifacts (Docker + K8s + Helm + Terraform)
    ↓
Observability (OTel + structured logging + correlation-id + SLOs)
    ↓
Release gate (7 checks AMX post-retro)
    ↓
Aggregate report pre-deploy
```

Todo esto lo ejecuta **Kiro autonomo** cuando instalas el Power `amx-aios-unified`.

---

## 2 · Qué entregué · métricas concretas

### Caso de prueba sintético · `frankenstein-70k`

Un codebase generado determinísticamente (Python · `tools/generate_frankenstein.py` · seed fijo · 1 comando) que simula un workload AMX real con las 27 categorías FRK del audit · escalado a 70K LoC.

| Métrica | Valor |
|---|---:|
| LoC totales | **70,265** |
| Archivos | 199 |
| Lenguajes | 6 (C# · Python · Java · COBOL · PHP · XML config) |
| Módulos | 10 (espejo de las 10 apps del scope revenue-accounting) |
| FRKs sembrados | 79 instancias de 26 patrones únicos |

### Resultado del refactor end-to-end

| Métrica | Valor |
|---|---:|
| **Wall-clock total** | **2h 49min** |
| **FRKs resueltos** | **79/79 ✅** (dentro del scope CWE del scanner) |
| **Build gates PASS** | **6/6** (4 CLI real · 2 syntax-manual · Java/COBOL) |
| **Tests** | 120/120 PHP regression PASS · C# xUnit PASS · Python 100% |
| **Commits atómicos** | 9 |
| **LoC nuevos** | **+62,522** (specs + tests + CI/CD + Docker + k8s + helm + terraform + docs) |
| **Detection (vs gold standard sintético propio)** | 100% precision/recall — caveat: era contra un SEED autogenerado · tautológico |
| **Detection (vs análisis humano experto NoShow)** | **25%** (7/28) — ver sección honestidad metodológica |
| **Release gate final** | **READY · 4/4 PASS** |

### Delta security_scan (ruido scanner eliminado iterativamente)

| Severidad | Pre-refactor | Post-refactor (v1.7.1) | v1.7.4 final | Delta |
|---|---:|---:|---:|---:|
| CRITICAL | 69 | 45 (FPs docs) | **0** | **-100%** |
| HIGH | 7 | 13 (FPs docs) | **0** | **-100%** |
| MEDIUM | 0 | 0 | 0 | 0 |
| **TOTAL** | **76** | 76 | **0** | **-100%** |

---

## 3 · Cómo encaja con AM-KIRO (tu framework)

AIOS está implementado como pack `manifest.json`-compatible con tu estructura AM-KIRO:

```
aios-framework/
├── manifest.json          ← dependencies: ["core"] · amx_compat_since: 1.7.1
├── .kiro/
│   ├── steering/          ← 10 archivos (6 ai-system/ + 4 AIOS rules)
│   ├── hooks/             ← 4 .kiro.hook (pre-task · post-session · security-gate · release-gate)
│   └── settings/          ← aios-settings.json con amx_overrides
├── aios/
│   ├── mcp_server.py      ← FastMCP server · 8 tools
│   ├── core/              ← spec-driven engine · security_gate · release_gate
│   └── policies/          ← AMX policy (amx-revenue-accounting)
└── powers/
    └── amx-aios-unified/  ← Kiro Power drop-in
        ├── POWER.md
        ├── mcp.json
        └── steering/
```

**Drop-in compatible** · cuando obtengas OYN-AMX autorice, ejecutas:

```bash
am-kiro install aios
```

y el pack queda registrado con su DAG de dependencies resuelto.

---

## 4 · Qué aprendí del workload real (útil para AM-KIRO)

Durante la validación descubrí **10 recomendaciones** concretas · 8 ya implementadas · 2 en BACKLOG:

| # | Recomendación | Status | Commit aios-framework |
|---:|---|---|---|
| R1 | `exclude_comment_lines` en Mythos scanner (filtra FPs de comentarios de trazabilidad) | ✅ v1.7.2 | `0943cb9` |
| R2 | `exclude_files` con glob patterns (`tools/**`, `deploy-ready/tests/**`) | ✅ v1.7.2 | `0943cb9` |
| R3 | STATIC-CMD-SHELL-TRUE verificado correcto (regex ya filtra `shell=True` exacto) | ✅ confirmado | `bacd323` |
| R4 | `release_gate_check` acepta phase=COMPLETED/DONE/PRE-DEPLOY | ✅ v1.7.2 | `1fd0db5` |
| R5 | `release_gate_check` reconoce pattern multi-módulo (N specs paralelos) | ✅ v1.7.2 | `1fd0db5` |
| R6 | Kiro UI expone solo 2 modos · cuando AIOS declara 4 | 📝 BUG-001 BACKLOG (host Kiro · no fix en pack) | `bacd323` |
| R7 | Checkpoint automático entre fases | ✅ v1.7.4 · `aios resume` + `aios checkpoint` CLI | `0fa5039` |
| R8 | Strip inline comments (edge case regex multi-línea) | ✅ v1.7.3 | `32606b8` |
| R9 | CREDENTIAL-PLAINTEXT-WEBCONFIG whitelist `arn:aws:secretsmanager:*` | ✅ v1.7.3 | `32606b8` |
| R10 | HARDCODED-INTERNAL-HOSTNAME whitelist `*.amx.internal` (Route53 PHZ) | ✅ v1.7.3 | `32606b8` |

Todo tracked en [BACKLOG.md](https://github.com/christianescamilla15-cell/aios-framework/blob/feat/am-kiro-compat/BACKLOG.md) del repo.

---

## 5 · Propuesta de contribución a OYN-AMX

### Qué propongo

1. **Acceso read de tu repo `OYN-AMX/am-kiro`** · para validar que el manifest de AIOS respeta el schema oficial AM-KIRO antes de abrir PR.
2. **Contribución del pack AIOS** · como `packs/aios/` en tu repo · o como submodule · según tu preferencia.
3. **Packs futuros** como iteración:
   - `mythos-pack` (depends: `core`, `security`) · 10 scanner agents avanzados
   - `arena-pack` (no existe contraparte · diferenciador eTrive)

### Qué NO propongo

- No propongo tocar `packs/core/` ni `packs/api/` que ya tienes publicados en Q1.
- No pido merge rights · solo feature branches con PRs para tu revisión.

### Formato de entrega

- **Repositorio**: `github.com/christianescamilla15-cell/aios-framework` (rama `feat/am-kiro-compat` · privado)
- **Demo**: `apps_code/frankenstein-70k/` en repo `amx-hallazgos-audit` (privado) · reproducible con 1 comando
- **Evidencia**: `docs/FINAL_REPORT_LM_FRK70K.md` · spec-driven completo · 22 items pre-deploy checklist
- **Contacto**: christianescamilla15@gmail.com · WhatsApp disponible

---

## 6 · Sobre los descubrimientos del workload real

Al validar sobre 70K LoC descubrí 2 cosas que merecen tu feedback:

1. **Kiro UI hostea solo 2 modos** (Build a Feature / Fix a Bug) aunque el manifest declare 4 (BUGFIX · FEATURE · MIGRATION · LEGACY_MODERNIZATION). Workaround: describir el intent explícitamente. Fix propuesto: que AM-KIRO lea `capabilities.modes` del manifest dinámicamente y popule el dialog.

2. **`mcp.json` env vars no se propagan consistentemente** al subprocess del MCP server. Validado con la instrumentación kcb durante el audit. No bloquea funcionamiento · pero afecta instrumentación/telemetría opcional.

Ninguno es urgente · pero si tu equipo tiene bandwidth · un issue en OYN-AMX cerraría la caja.

---

## 7 · Próximos pasos propuestos

1. **15 min call** cuando te acomode · te demo el refactor FRK70K end-to-end en Kiro
2. **Acceso OYN-AMX read** · yo corrió mi pack contra tu schema oficial
3. **PR feature branch** · abro el PR y tu equipo revisa cuando tengan bandwidth

Estoy disponible cualquier momento esta semana.

---

**Archivos referenciados para diligencia técnica** (cuando requieras verificar):

| Qué | Dónde |
|---|---|
| Código fuente AIOS | `github.com/christianescamilla15-cell/aios-framework` (rama `feat/am-kiro-compat`) |
| Tag latest | v1.7.4 |
| Power drop-in | `aios-framework/powers/amx-aios-unified/` |
| Reporte final del refactor 70K | `amx-hallazgos-audit/apps_code/frankenstein-70k/docs/FINAL_REPORT_LM_FRK70K.md` |
| BACKLOG con fixes tracked | `aios-framework/BACKLOG.md` |
| Gold standard del caso de prueba | `amx-hallazgos-audit/apps_code/frankenstein-70k/SEED_EXPECTED_FINDINGS.json` |

---

*Este documento es evidencia operativa · no replace un playbook oficial de gobierno. Todo commits firmados · repos privados · ningún secreto real AMX incluido (los forbidden_literals del audit están en catálogo interno amx-hallazgos-audit con access control).*

---

## Anexo · 4 detectores que el framework debería tener (aprendidos del análisis humano NoShow)

Estos son los patrones que humano experto detecta pero Mythos no. Propuesta para v1.8:

| Detector propuesto | Qué captura | Ejemplo NoShow |
|---|---|---|
| `BUSINESS-HARDCODED-VALUES` | números de vuelo · route codes · SKUs · IDs pinned | `if (pnr.Flight == "829")` |
| `CROSS-FOLDER-CONFIG-DRIFT` | divergencia semántica prod vs test vs qa configs | `test.config` vs `prod.config` con mismos secrets reales |
| `SECRETS-IN-TEST-CONFIGS` | secretos reales en configs marcados test/qa/staging | `test.config` con `S4tP@ssw0rd` real |
| `CODE-MARKED-FOR-REMOVAL` | TODO-REMOVE · DEPRECATED · stubs olvidados entre iteraciones | `// TODO: remove before release` de hace 6 meses |

Estos NO son CWE estándar · son **patrones operativos de dominio** que requieren heurística semántica + cross-file analysis. Son exactamente lo que el análisis humano NoShow capturó y yo perdí.

Si tu equipo AM-KIRO tiene patrones similares propios, lo podemos co-desarrollar. Esto cierra la brecha "framework vs humano experto" de 25% → mayor.
