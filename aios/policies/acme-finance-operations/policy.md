# ACME Finance Operations Policy

Policy tropicalizada para el proyecto Finance Operations Modernization · AcmeAir · Etrive + Miatech. Extiende `enterprise` con constraints específicos ACME.

## Scope
Aplica a los 10 aplicativos del scope: FleetOpsApp · Reembolsos ARC · Reembolsos BSP · CFDIs · SRG · ASR · Robot Cálculo · Comisiones Directas · Comisiones Indirectas · NoShow Report.

NO aplica a: Facturación Electrónica MX · Revenue Recognition · TNU · Interlineal · FEBOL · RAM (anti-scope).

## Constraints ACME (obligatorios · no negociables)

### Arquitectura cloud
- **ECS PROHIBIDO** (por decisión ACME · constraint de arquitectura empresarial)
- **Alternativas permitidas:** EC2 con docker-compose · EKS · Fargate (si autorizado por Diego Zarate)
- **Akamai MANDATORIO** para endpoints públicos (WAF + CDN + DNS)
- **VPC** dedicada por cuenta AWS · CIDR coordinado con Diego Zarate

### Seguridad y escaneos
- **4 escaneos OBLIGATORIOS pre-prod** antes de cualquier release:
  1. **Tenable** — IaC / infraestructura
  2. **Veracode** — código fuente (C# / Python / Java / PHP / COBOL)
  3. **WIZ** — AWS landscape (CSPM)
  4. **Prisma Cloud** — contenedores (si aplica)
- **Cero credenciales hardcoded** — usar AWS Secrets Manager o Vault (Bolt/HashiCorp)
- **KMS gestionado por ACME** — no por Etrive · usar CMK según autorización seguridad AWS ACME
- **Rotación de credenciales trimestral** mínimo

### Ambientes
- **NO existe QA en ACME** · todo va directo a PROD en corporativo · DEV debe crearse localmente por cada app
- **VPN** como prereq universal · cada dev necesita VPN configurada
- **Ambiente DEV obligatorio** antes de refactor (no se puede refactorizar en PROD)

### Gates de release
- **5 checkpoints SDLC ACME obligatorios:**
  1. Discovery gate
  2. Design gate (arquitectura aprobada)
  3. Build gate (4 escaneos OK)
  4. Test gate (cobertura ≥ mínimo por app)
  5. Release gate (rollback plan + runbook)
- **Definition of Done corporativa ACME** aplica a cada release
- **Gate reviews** presentados al PMO ACME

### CI/CD
- **GitHub Actions** para pipeline (sin excepciones)
- **AWS CodeDeploy** para deployment
- **Docker** (no Kubernetes · decisión equipo 16-abr)
- **Contenedores con hardening ACME** · usar Golden Image / AMI custom (no genéricas)

### Gobernanza
- **ADR obligatorios** para decisiones de arquitectura (Architecture Decision Records)
- **Risk register** al día · actualizado por Líder Técnico
- **PII policy** cumplida si aplica (track activo 70 procesos · aplica a Especiales/ASR)
- **Compliance:** ISO 27001 · SOC 1 · PCI (si aplica por app)
- **ServiceNow workflow approvals** para cambios infra

### Stack específicos
- **COBOL** solo Comisiones Directas (#8 · AS400 Perú) y Comisiones Indirectas (#9 · ILE embebido) · ambas STANDBY
- **COBOL → Python:** no traducir línea a línea · equivalencia funcional (decisión 15-abr)
- **.NET:** migrar 4.6.1 / 4.7.2 → .NET 8 LTS antes de EOL enero-2026

### Testing
- **Cobertura mínima:**
  - FLEET_OPS_APP: 40% (baseline 0%)
  - ARC/BSP/ASR: 50%
  - Robot #7: 60% (crítico · motor central)
  - NoShow: 60% (4 hallazgos CRITICAL)
  - Comisiones: 40% (reactivación)
  - CFDIs/SRG: 40%
- **Dataset histórico** para validación (mínimo 6 meses)
- **Paralelo mandatorio** entre legacy y nueva versión (4-8 semanas según criticidad)

### Prohibido explícitamente
- Cambiar credenciales SABRE sin autorización (TANPUL limit 2000 sessions)
- Modificar Sistema "Balanceador" (es del cliente · solo integrar)
- Eliminar Stored Procedures sin audit previo (71 en FLEET_OPS_APP · 67 obsoletos detectados)
- Deploy manual a PROD sin CI/CD post-estabilización
- Tocar BD de Praxis Core (solo Miatech directo)

## Política por modo

### BUGFIX
- Tests de regresión específicos del bug
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

## Aprobadores

| Tipo de cambio | Aprobador |
|---|---|
| Arquitectura | Toño (IT Drive · consultor AWS ACME) |
| CI/CD | Diego Zarate (red AWS) |
| Seguridad | Carlos Reyes (Miatech) / Ciberseguridad ACME |
| KMS / Secrets | Equipo seguridad AWS ACME |
| Red / VPC | Diego Zarate + Ciberseguridad ACME |
| Contratos / scope | Víctor Araiza (PM) |
| Compliance / PII | Elias Tapia + ACME Personal Data |
| Release a PROD | Víctor + Líder Técnico + 5 gates OK |

## Contactos clave
- **PM:** Víctor Araiza
- **Líder Técnico:** Christian Hernández
- **Experto COBOL:** Gustavo Magallanes (standby #8 #9)
- **Manager cuenta Etrive:** Eloisa Sánchez
- **Program Manager ACME:** Luis Ertuche (Sertuche)
- **Sponsor ACME:** Elias Tapia
- **Revenue owner ACME:** J.T. (VP Revenue · Javier Toledo Tovar)

## Referencias
- Memoria principal: `project_scope.md` · `project_aws_migration_constraints.md`
- Matriz accesos: `project_matriz_accesos.md` (V3 · 74 accesos)
- Timeline: `project_timeline_abril.md`
- Sesiones upcoming: `project_upcoming_sessions.md`

## Versionado
- **v1.0** · 17-abr-2026 · creación inicial por Christian Hernández.
- Actualizar al cerrar cada sprint / milestone · agregar lecciones aprendidas.
