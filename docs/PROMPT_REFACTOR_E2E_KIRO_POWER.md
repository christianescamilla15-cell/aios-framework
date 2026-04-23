# Prompt · Refactorización end-to-end en Kiro con Power amx-aios-unified v3.3.1

Prompt self-contained para Kiro · LEGACY_MODERNIZATION mode · cubre desde discovery hasta pre-deploy. Basado en NoShow como ejemplo concreto · adaptable a cualquiera de las 10 apps AMX.

---

## Prompt para copy-paste a sesión nueva de Kiro

```
Modo: LEGACY_MODERNIZATION · refactor end-to-end

Power activo: amx-aios-unified v3.3.1 (lo tengo instalado · pip aios-framework v3.3.1 también)

Proyecto target: ATOS-NOSHOW-ROBOT
Ubicación source (decompilado): C:\Users\eTriber\Downloads\ATOS-NOSHOW-ROBOT\ATOS-NOSHOW-ROBOT
Ubicación build (binarios prod): C:\Users\eTriber\Downloads\NoshowReport\NoshowReport
Spec humano baseline: C:\Users\eTriber\Desktop\amx-hallazgos-audit\apps\10-noshow\Analisis_NoShow_para_sesion_23abr.md (28 findings audit humano v2)

Stack objetivo (confirmado con Antonio H. Oropeza + retro 20-abr):
- .NET Framework 4.7.2 → **.NET 8 LTS** (EOL ene-2026 bloqueador)
- Windows Service on-prem → **AWS Fargate** (sin ECS · sin SES · sin SNS)
- Quartz.NET 2.3.3 EOL 2023 → **AWS EventBridge** managed cron
- SQL Server on-prem (AIDX) → **RDS** (ya migrado 2026-04-21 · endpoint nuevo)
- Renci.SshNet 2016 → **AWS Transfer Family SFTP**
- log4net + texto plano → **Serilog + CloudWatch Logs** (structured + PII redaction)
- 6 creds plaintext → **AWS Secrets Manager + KMS CMK dedicada**
- 0% test coverage → **xUnit ≥ 60% business-critical**
- Deploy manual → **CodePipeline CDK Corp Solutions AMX estándar**
- Route53 PHZ interno para endpoints SABRE · SMTP relay · SFTP

Features nuevos (pedidos Javi Toledo sesión 22-abr):
- Pantalla admin React + Cognito (grupos NoShow-Admins / NoShow-Viewers)
- Parámetros editables vía Parameter Store: HRSMAX ventana detección · cron · OUTOFSCOPE prefixes · dist list emails
- Modo ejecución ad-hoc por vuelo (reemplaza hardcode "829" hoy en MainServices.cs:57)
- Dashboard monitoreo (última ejecución · count registros · SFTP upload status · email status)
- Audit trail de cambios de parámetros

Owner funcional nuevo: Elías Tapia + Braulio (Revenue/Data · NO Aeropuertos)
PM: Luis Ertuche · deadline flex Nov-2026 · diciembre buffer sin romper compromiso
Revenue stakeholder: Javier Toledo (feature requests)

─── FASE 0 · Discovery & Baseline ───

1. Lee y resume los 28 findings del audit humano del 23-abr
2. Corre el MCP tool `security_scan` sobre source y build
3. Corre `release_gate_check` · reporta status
4. `characterize --capture` los archivos .cs clave (MainServices, SabreAdapter, SFTPAdapter, EmailAdapter, SabreBO) para congelar API contract pre-refactor
5. `drift --source <source-tree> --compare <build>` para mapear divergencias source↔prod (las 3 configs · TargetFramework · endpoints SABRE CERT vs PROD · passwords cross-env)

Entregable Fase 0: reporte markdown con baseline · no escribir código aún

─── FASE 1 · Spec Generation (EARS) ───

Usa el mode spec-driven del Power amx-aios-unified:

1. Requirements en formato EARS · incluye:
   - Requirements funcionales derivados del binario actual (preserve behavior)
   - Requirements nuevos: pantalla admin · modo ad-hoc · dashboard
   - Requirements no-funcionales: .NET 8 · Fargate · Secrets Manager · Serilog · xUnit 60%+
   - Compliance requirements: LFPDPPP redaction PII · SOX audit trail (si confirma Elías) · 4 gates AMX scan (Veracode · Tenable · WIZ · Prisma) target 0 HIGH/CRITICAL

2. Design.md · incluye:
   - Arquitectura target con diagrama componentes AWS
   - ADR por cada decisión no-trivial (logging · secrets · cron · admin UI)
   - Mapeo each finding humano → acción concreta en refactor
   - Paridad funcional: cron 06:50 · SFTP /CADUCOS · TXT pipe-delimited 24-col · SABRE XON · filtros USED/VOID/EXCH/RFND · OUTOFSCOPE prefixes

3. Tasks.md · incluye:
   - ≥10 tasks con BLOCKERS marcados para gates AMX críticos
   - Owner por task · estimate en días · dependencies
   - Pre-deploy gates como tasks bloqueantes

Entregable Fase 1: requirements.md · design.md · tasks.md bajo aios-framework/specs/noshow-modernization/

─── FASE 2 · Iterative Refactor por módulo ───

Para CADA módulo (Business · Data · NoshowWS + nuevo AdminUI):

A. Implementa cambios respetando el design.md
B. Después de cada cambio significativo:
   - `security_scan` · verifica findings no se introdujeron
   - `iterate --strategies regex,ensemble,cross_file_taint --max-iterations 3`
   - Si quedan findings HIGH · `classify --file X --line N --provider anthropic --model claude-sonnet-4-6`
     (usa Opus si es finding crítico · Sonnet para volumen · Haiku para CI masivo)
   - `review list` · gestiona los pending pause_for_review · approve/reject/defer

C. Tests con xUnit:
   - Replica cobertura sobre behavior congelado en characterize
   - `characterize --verify` · confirma 0 deltas breaking
   - Si hay delta · resolver ANTES de continuar (no acumular)

D. Commit por micro-feature · convencional commits · referencia finding humano cerrado

─── FASE 3 · Gates AMX pre-deploy ───

Ejecuta en orden · BLOCKERS:

1. `release_gate_check` final · target:
   - Security static scan: 0 CRITICAL · 0 HIGH (tras refactor)
   - Domain-aware review: 0 pending unclear
   - Behavior preservation: 0 breaking vs baseline characterize
   - SITL queue: 0 pending · todos approved con razón
   - Risk docs: risks.md presente · actualizado

2. `drift --source <refactored> --compare <last-prod-build>` · documenta drifts INTENCIONALES (target framework .NET 8 · endpoints RDS · Secrets Manager refs) · marcar en risks.md

3. `exfil --root <refactored> --corporate "aeromexico.com.mx,am.com.mx,aeromexico.com"` · verifica que:
   - NO hay emails nuevos a dominios no-corporativos
   - Miatech.net removido del dist list (o documentado como partner autorizado)

4. `runtime-data --root <logs-dir-de-staging>` · PII redaction funciona:
   - PNRs masked en logs Serilog staging run
   - Nombres pasajero · ticketNumber · CURP redactados
   - 0 HIGH (tokens · PAN · JWT) · 0 MEDIUM PII en logs staging

5. Gates corporativos AMX (externos · 4 escaneos · cada uno blocker):
   - **Veracode**: submit SAST · target 0 CRITICAL/HIGH
   - **Tenable**: scan infra · target 0 CRITICAL
   - **WIZ**: cloud posture scan · target ≤1 MEDIUM
   - **Prisma**: container scan · target 0 CRITICAL en imagen Fargate
   Reporta resultados + evidencia en compliance-report.md

6. `dynamic-hooks --root . --findings-file findings.json` · genera:
   - xUnit integration test stubs para los métodos refactorizados
   - Reglas Falco para runtime observability (CWE-532 PII · CWE-78 shell spawn · CWE-89 SQL injection · CWE-664 runtime exception)
   - Sugerencias OpenTelemetry spans para SABRE SOAP calls · SFTP upload · SMTP send

─── FASE 4 · Pre-deploy validation ───

1. Correlation-id funcional end-to-end (retro 20-abr requirement)
2. Health endpoint HTTP (.NET 8 built-in) + métricas CloudWatch custom
3. Secrets rotation trimestral configurado · KMS CMK dedicada por servicio · no compartir
4. IAM roles con prefijo `amx-r-*` · GateOne portal provisioning OR AMX Chat Service Desk
5. Akamai WAF enfrente si hay entry point HTTP (admin UI)
6. Backup + rollback plan documentado en runbook.md
7. Smoke test en staging con datos sintéticos · valida paridad vs binario legacy
8. Load test mínimo · confirma no hay race en singletons refactorizados (DR-04 · DR-08 · DR-15 del clean session pilot)

Entregable Fase 4: evidence bundle con:
- Reporte de los 4 gates AMX (Veracode · Tenable · WIZ · Prisma)
- Release gate final passing (0 CRITICAL · 0 HIGH)
- Test coverage report (≥60%)
- Runbook
- ADRs firmados por arquitectos + Ciber
- Approval email trail con Elías Tapia (owner funcional) + Luis Ertuche (PM)

─── FASE 5 · Deploy (gated) ───

Solo si Fase 4 pasa sin rojos:

1. Deploy via CodePipeline CDK · no manual
2. Monitoreo post-deploy 72h: alertas CloudWatch · correlation-id traza · log redaction funcionando
3. Rollback automático si métricas SLO degradan >10% vs baseline

─── Constraints operativos durante toda la sesión ───

- NO usar ECS · usar Fargate (retro 20-abr)
- NO usar SES · usar relay interno AMX con TLS + STARTTLS 587
- NO usar SNS para email · EventBridge o SQS si pub/sub
- KMS CMK separada por servicio · NO compartir
- Observabilidad con correlation-id · CloudWatch + Akamai logs
- GitHub Enterprise única SoT (no GitLab · no Miatech on-prem)
- Pre-confirmar con líder AMX (Víctor Araiza) antes de escalar tickets GateOne
- Respeta el flujo aprobación v2.0 del 21-abr

─── Honestidad metodológica ───

- Coverage del framework sobre findings humanos: 53-65% medido (2nd clean session) · 18% irreductible (compliance SOX/LFPDPPP · decisiones producto · deploy governance)
- NUNCA prometer 99.99% · es físicamente imposible por Rice's theorem
- SÍ prometer: 2-3x mejor que SAST comercial sobre código real + 4 detectores únicos (drift · credential byte-identity · exfil · runtime PII) + 2 bugs revenue-críticos (`.Hours` misuse · substring name matching) que ni el auditor humano listó
- Framework es complemento · NO sustituto del análisis humano senior

─── Checkpoint final ───

Antes de declarar Fase 4 completa, responde (1 línea cada una):
- ¿Qué findings humanos v2 del audit 23-abr quedaron sin resolver? (lista IDs)
- ¿Qué deltas entre source decompilado y nueva implementación son intencionales vs no?
- ¿El behavior preservation tiene 0 CRITICAL characterization delta?
- ¿Los 4 gates AMX externos (Veracode · Tenable · WIZ · Prisma) pasaron todos?
- ¿Elías Tapia aprobó explícitamente vía email + ticket GateOne?

Si alguno es NO → iterar · NO deployar.
```

---

## Cómo usarlo

1. Abre Kiro con el workspace del proyecto target
2. Verifica que el Power `amx-aios-unified v3.3.1` está activo (Command Palette → `Developer: Reload Window` si es la primera vez post-install)
3. Pega el prompt completo en el chat de Kiro
4. El agente va a pedir confirmaciones en puntos clave (MCP trust list · ejecución de scans · commits). Responde según tu criterio.
5. Cada fase entrega un artefacto medible · si algo falla o se desvía, interrumpe y pide al agente revisar vs el design.md

## Adaptación para otras 9 apps AMX

Cambia estas variables al inicio del prompt:

Variable	NoShow (ejemplo)	Para otras apps
`Proyecto target`	ATOS-NOSHOW-ROBOT	01-sicofav · 02-arc · 03-bsp · etc
`Spec humano baseline`	Analisis_NoShow_para_sesion_23abr.md	`apps/<NN-name>/*.md` del audit
`Stack objetivo`	.NET 4.7 → .NET 8 · Fargate	adaptar según stack origen
`Owner funcional`	Elías Tapia + Braulio	según app (ver catálogo Nemesis `engagement_list()`)
`Deadline`	Nov-2026	Luis Ertuche confirma por app
`Features nuevos`	Admin UI + modo ad-hoc	específicos por app

## Tiempo esperado

Fase	Duración estimada
0 · Discovery	0.5-1 día
1 · Spec	1-1.5 día
2 · Iterative refactor	5-10 días (depende complejidad app)
3 · Gates AMX pre-deploy	2-3 días (4 scanners externos pueden tardar)
4 · Pre-deploy validation	1-2 días
**Total por app**	**10-17 días laborables**

Para NoShow (1.5 KLoC) · techo inferior ~8-10 días. Para SICOFAV/ARC (20-40 KLoC) · techo superior ~15-20 días.

## Output esperado de Kiro

Al completar el prompt end-to-end, el agente deberá entregar:

```
noshow-modernization/
├── specs/
│   ├── requirements.md    · EARS format · trazable a 28 findings
│   ├── design.md          · ADRs + arquitectura target AWS
│   ├── tasks.md           · 109+ tasks con BLOCKERS gates AMX
│   └── risks.md
├── src/                   · .NET 8 refactorizado
├── tests/                 · xUnit ≥60%
├── infrastructure/        · CDK stacks
├── .aios/
│   ├── characterization/  · API fingerprints baseline
│   ├── reviews/           · SITL audit trail
│   └── reports/           · aggregate reports por fase
├── docs/
│   ├── runbook.md
│   ├── compliance-report.md  · Veracode/Tenable/WIZ/Prisma evidence
│   └── evidence-bundle.md    · pitch ejecutivo Elías + Luis
└── CHANGELOG.md
```
