# AMX Revenue Accounting Policy

Policy tropicalizada para el proyecto Revenue Accounting Modernization · Aeroméxico · Etrive + Miatech. Extiende `enterprise` con constraints específicos AMX derivados de retros 20-abr-2026 (arquitectos · DevOps · Ciberseguridad) y flujo aprobación v2.0 21-abr.

## Versión vigente

- **v2.0 · 21-abr-2026** · incorporación reglas retro 20-abr + flujo aprobación v2.0 · resuelve contradicciones v1.0 (Docker/K8s · orden escaneos · EC2)
- v1.0 · 17-abr-2026 · DEPRECATED (superada por v2.0)

Cambios v1.0 → v2.0:
- ECS prohibido alineado con retro Antonio · EC2 prohibido en T0/T1 · EKS o serverless obligatorio
- Orden escaneos CYBER corregido: WIZ → Veracode → Prisma → Tenable (antes incorrecto: Tenable → Veracode → WIZ → Prisma)
- Eliminada regla "Docker (no Kubernetes)" · contradecía EKS mandatorio para T0/T1
- Incorporadas 9 gates formales (antes solo 5 checkpoints genéricos)
- Añadidas reglas IAM amx-r-* · SES/SNS prohibidos · KMS una por servicio · plataformas obligatorias AMX · proceso tickets
- Añadidos aprobadores: Israel Miguel González (Borde Arq) · Miguel Rachid (Ciber gate final)

## Scope

Aplica a los 10 aplicativos: Sicofav · Reembolsos ARC · Reembolsos BSP · CFDIs · SRG · ASR · Robot Cálculo · Comisiones Directas · Comisiones Indirectas · NoShow Report.

NO aplica a (anti-scope): Facturación Electrónica MX · Revenue Recognition · TNU · Interlineal · FEBOL · RAM.

## 1. Constraints arquitectónicos AMX (retro Antonio 20-abr · no negociables)

### 1.1 Compute · servicios AWS permitidos y prohibidos

**Prohibidos:**
- **ECS** · severity CRITICAL · alternativa: EKS (Kubernetes)
- **SES** · severity HIGH · alternativa: relay interno AMX
- **SNS para email** · severity HIGH · solo eventos · alternativa: relay AMX

**Arquitectura obligatoria por Tier** (doc oficial pendiente Dynamo · Edgar Castillo):

| Tier | Descripción | Arquitectura mandatory | EC2 permitido |
|---|---|---|---|
| **T0** | Misión crítica 24×7 · revenue direct | EKS o Serverless (Lambda) | ❌ |
| **T1** | Apps satelitales críticas · compliance | EKS o Serverless (Lambda) | ❌ |
| **T2** | Operación normal · menor criticidad | EC2 · EKS · Serverless | ✅ |

> ⚠️ **Tier oficial por app:** pendiente obtener doc Dynamo. Hasta entonces · tiers en policy son HIPÓTESIS documentadas con inconsistencia P0 (ver sección 11).

### 1.2 Akamai al frente · MANDATORIO

- WAF + CDN + DNS para todo endpoint público
- Sin excepciones

### 1.3 Zero Trust · meta fin de año 2026

- Roadmap ADR requerido Q2 · implementación progresiva Q3-Q4
- Milestone en Plan Maestro · trackear

## 2. Flujo aprobación v2.0 · 9 gates formales (21-abr)

Orden estricto · no pedir fierros (VPC · KMS) antes de diseño aprobado por Borde Arq.

| # | Gate | Contacto | SLA / Obs |
|---|---|---|---|
| 1 | **óptimo · alta proyecto** | Carina | registro inicial |
| 2 | **Diagramas C4 en LeanIX** | Borde Arquitectura | plataforma oficial |
| 3 | **ADR · opción A vs B** | arquitectura AMX | obligatorio · con trade-offs |
| 4 | **Borde de Arquitectura aprobación** | Israel Miguel González Sandoval | gate bloqueante |
| 5 | **Cuenta AWS AMX** | Víctor Araiza (líder AMX) | SLA 24h |
| 6 | **VPC + subnets** | Diego Zarate | coordinar CIDR |
| 7 | **KMS tickets** (1 por servicio) | Antonio H. Oropeza + líder AMX | 1 CMK por servicio · no compartir |
| 8 | **Escaneos CYBER** (secuencia) | Miguel Rachid + equipo CYBER | ver sección 3 |
| 9 | **Miguel Rachid · gate final** | Miguel Rachid | aprobación ciber release |

## 3. Escaneos CYBER · secuencia obligatoria

### 3.1 Orden correcto (retro 20-abr)

| Orden | Herramienta | Scope |
|---|---|---|
| 1 | **WIZ** | AWS cloud posture (CSPM) |
| 2 | **Veracode** | static code analysis (C# · Python · Java · PHP · COBOL) |
| 3 | **Prisma Cloud** | contenedores + compute |
| 4 | **Tenable** | infrastructure as code |

### 3.2 Criterio aceptación

- **Prácticamente cero HIGH/CRITICAL** · suppressions documentadas con waiver
- Todos los HIGH/CRITICAL no suprimidos bloquean release

### 3.3 Loop iterativo (NO lineal)

Cyber es iterativo: scan → fix → re-scan → approve. No es un evento único pre-prod.

- Post-patch · re-scan obligatorio del scope tocado
- Cada iteración documentada en release notes

## 4. IAM · roles y políticas

### 4.1 Prefijo obligatorio `amx-r-*`

- Enforced por SCPs (Service Control Policies)
- Validado por `security_gate.py` · función `check_role_prefix(role_name)`

### 4.2 Dos roles principales por cuenta AWS

| Rol | Requiere | Privilegios extra | No puede modificar |
|---|---|---|---|
| **ATR** | YubiKey | Sí | KMS · policies organizacionales |
| **desarrollo** | standard | No | KMS · policies organizacionales |

## 5. KMS · claves gestión

- **Una CMK por servicio** (sin compartir)
- Gestionadas por AMX · no por Etrive
- Provisioning: GateOne portal autoservicio OR AMX Chat Service Desk
- Requisitos:
  - Correo visto bueno del líder AMX previo
  - Captura del correo adjunta al ticket
  - Aplicación vía IaC (CloudFormation · CDK)

## 6. Plataformas AMX obligatorias

| Plataforma | Uso |
|---|---|
| **óptimo** | project management registry |
| **LeanIX** | diagramas C4 de arquitectura |
| **GitHub Enterprise** | single source of truth del código (NO GitLab · NO Miatech on-prem) |
| **GateOne** | portal autoservicio tickets |
| **AMX Chat Service Desk** | portal alternativo tickets |
| **ServiceNow CMDB** | trazabilidad Jira · commit → release cycle |
| **Dynamo** | documentación madurez + doc TIERS oficial |

## 7. Proceso estándar de ticket AMX

1. Líder AMX directo envía correo previo con visto bueno
2. Levantar ticket en GateOne (o AMX Chat Service Desk)
3. Adjuntar captura del correo como evidencia
4. Esperar SLA (24h laborales para cuenta AWS · variable otros recursos)
5. Recibir respuesta vía correo con ID del recurso

## 8. Secretos · credenciales

- **Cero credenciales hardcoded** (ni código · ni configs · ni appSettings)
- Usar AWS Secrets Manager o Vault (Bolt / HashiCorp según app)
- **Rotación trimestral mínima**
- Validar con Veracode + manual review pre-release

## 9. Ambientes

- **NO existe QA en AMX** · todo va directo a PROD en corporativo
- **DEV local** obligatorio · por dev + por app
- **VPN AMX** como prereq universal · cada dev necesita VPN configurada
- **Paralelismo legacy ↔ nueva versión** 4-8 semanas según criticidad (MIGRATION / LEGACY_MODERNIZATION)

## 10. CI/CD · DevOps

- **GitHub Actions** (sin excepciones)
- **AWS CodeDeploy** para deployment
- **Contenedores** con hardening AMX · Golden Image / AMI custom (no genéricas)
- **SAST** per stack en pipeline · bloqueante en HIGH/CRITICAL
- **DORA Metrics** tracked (roadmap P1 · pendiente integración)
- **15 entregables DevOps** (Alexis · retro 20-abr · checklist formal pendiente P1)

## 11. TIERS · inconsistencia detectada (P0 resolver)

Luis Ertuche (verbal 21-abr 13:35): «CFDIs + SRG = T1 · demás T2».

Inconsistencias vs criterio arquitectónico Fer Pérez (4 graves):

| App | Luis | Criterio arq | Consistencia |
|---|---|---|---|
| SICOFAV | T2 | **T0-T1** · core facturación SOX | 🔴 INCONSISTENTE |
| BSP | T2 | **T1** · cierre diario IATA | 🔴 INCONSISTENTE |
| ARC | T2 | **T1** · compliance ARC USA | 🟠 SUB-clasificado |
| Robot #7 | T2 | **T0-T1** · motor 3 apps · CVSS 9.8 · PCI | 🔴 **GRAVE** |
| SRG | T1 | **T2** · 8x5 · no-core · sin compliance | 🟠 SOBRE-clasificado |

**Acción P0:** escalar obtención doc TIERS oficial Dynamo (Edgar Castillo + Israel Miguel). Hasta entonces · validator `get_tier_architecture()` emite warning y no bloquea.

## 12. Gobernanza

- **ADR obligatorios** para decisiones de arquitectura (Architecture Decision Records · opción A vs B con trade-offs)
- **Risk register** al día · actualizado por Líder Técnico
- **PII policy** cumplida si aplica (track 70 procesos · activo Especiales/ASR)
- **Compliance:** ISO 27001 · SOC 1 · PCI (si aplica por app · Robot #7 · ASR · Comisiones)
- **ServiceNow workflow approvals** para cambios infra

## 13. Stack específicos · mapeo oficial

### Stack por app

| # | App | Stack oficial |
|---|---|---|
| 1 | Sicofav | C# + ASP.NET 4.6.1 + VB.NET + PHP |
| 2 | ARC | Python 3.11 + Flask 2.2 + ReactJS + MySQL |
| 3 | BSP | JS + Java + Python · JDK/SDK |
| 4 | CFDIs | .NET |
| 5 | SRG | C# .NET 7 + Angular 15 + Windows Server 2012 R2 + IIS + SQL Server (confirmado workshop 21-abr) |
| 6 | ASR | Python + Flask + ReactJS · sobre Cobol legacy |
| 7 | Robot Cálculo | .NET · SABRE · TANPUL 2000 |
| 8 | Comisiones Directas (STANDBY) | COBOL + Java + HTML · AS400 DB2 V7R4M0 Perú |
| 9 | Comisiones Indirectas (STANDBY) | PHP + Python + COBOL ILE · ExtJS · AWS Aurora |
| 10 | NoShow | .NET 4.7.2 · C# · WinExe · SABRE SOAP · SFTP |

### Reglas stack

- **COBOL → Python:** equivalencia funcional · NO traducción línea a línea (decisión 15-abr)
- **.NET legacy:** migrar 4.6.1 / 4.7.2 → .NET 8 LTS antes de EOL enero-2026

## 14. Testing

### Cobertura mínima

| App | Target | Baseline |
|---|---|---|
| SICOFAV | 40% | 0% |
| ARC / BSP / ASR | 50% | variable |
| Robot #7 | 60% | crítico · motor central |
| NoShow | 60% | 4 CRITICAL activos |
| Comisiones | 40% | reactivación |
| CFDIs / SRG | 40% | nuevo |

### Validación

- **Dataset histórico** mínimo 6 meses
- **Paralelo mandatorio** entre legacy y nueva versión (4-8 semanas según criticidad)

## 15. Prohibido explícitamente

- Cambiar credenciales SABRE sin autorización (TANPUL limit 2000 sessions)
- Modificar Sistema "Balanceador" (del cliente · solo integrar)
- Eliminar Stored Procedures sin audit previo (71 en SICOFAV · 67 obsoletos)
- Deploy manual a PROD sin CI/CD post-estabilización
- Tocar BD Praxis Core (solo Miatech directo)
- Push a GitLab / Miatech on-prem (GitHub Enterprise es SSoT)

## 16. Política por modo

### BUGFIX
- Tests regresión específicos del bug
- Feature flag para activación gradual
- Rollback plan simplificado
- Approval Víctor + Christian

### FEATURE
- Spec completa (requirements · design · tasks · risks · rollback · validation)
- Design review con Toño (arquitectura AWS)
- Approval gate por fase

### MIGRATION
- Spec completa + `rollout.md` + `risks.md` + `rollback.md`
- Phased rollout obligatorio (0% → 10% → 50% → 90% → 100%)
- Ventana paralelismo 4-8 semanas
- Migration plan firmado por Luis Ertuche

### LEGACY_MODERNIZATION
- Spec completa + `modernization-roadmap.md`
- Quick Wins primero · High-Risk al final
- Tests antes de refactor mayor
- Code audit (Veracode) ANTES de refactor

## 17. Aprobadores

| Tipo de cambio | Aprobador |
|---|---|
| Arquitectura · diseño | Toño (IT Drive · consultor AWS AMX) + **Israel Miguel González Sandoval (Borde Arquitectura)** |
| CI/CD · red AWS | Diego Zarate |
| Seguridad · código | Carlos Reyes (Miatech) / Ciberseguridad AMX |
| **Ciber · gate final release** | **Miguel Rachid (Gerente Ciberseguridad AMX)** |
| KMS / Secrets | Antonio H. Oropeza + líder AMX + equipo seguridad AWS AMX |
| Red / VPC | Diego Zarate + Ciberseguridad AMX |
| Contratos / scope | Víctor Araiza (PM) |
| Compliance / PII | Elias Tapia + AMX Personal Data |
| Release a PROD | Víctor + Líder Técnico + 9 gates OK |

## 18. Contactos clave

- **PM:** Víctor Araiza
- **Líder Técnico:** Christian Hernández
- **Experto COBOL:** Gustavo Magallanes (standby #8 #9)
- **Manager cuenta Etrive:** Eloisa Sánchez
- **Program Manager AMX:** Luis Ertuche (Sertuche)
- **Sponsor AMX:** Elias Tapia
- **Revenue owner AMX:** Javier Toledo Tovar (J.T. · VP Revenue)
- **Borde Arquitectura AMX:** Israel Miguel González Sandoval
- **Gerente Ciberseguridad AMX:** Miguel Rachid
- **Arquitecto AWS AMX:** Antonio Hernández Oropeza
- **DevOps madurez:** Martín Alexis Martínez Hernández
- **Corp Solutions pipelines:** Rigoberto Texmayer Gaona

## 19. Referencias

- Memoria principal: `project_scope.md` · `project_aws_migration_constraints.md`
- Matriz accesos: `apps/Accesos_10Apps_Consolidado.xlsx` (actualizado 21-abr)
- Timeline: `project_timeline_abril.md` + `excel/Plan_Maestro_General.xlsx` (23 sem · 50 act · 245 subtareas)
- Sesiones upcoming: memoria `project_martes_21abr_sesion_completa.md`
- Constraints retro 20-abr: `aios-framework/aios/policies/amx-revenue-accounting/constraints_retro_20abr.py`
- Pre-flight AIOS 21-abr: `sesiones/21-abr_preflight_aios/REPORTE_AIOS.md`

## 20. Versionado

- **v2.0** · 21-abr-2026 · incorporación reglas retro 20-abr + flujo aprobación v2.0 · Christian Hernández
- v1.0 · 17-abr-2026 · creación inicial · DEPRECATED

Actualizar al cerrar cada sprint / milestone · agregar lecciones aprendidas.
