# AWS Stack Rules

> ⚠️ **AMX override activo:** Si la política del proyecto es `amx-revenue-accounting`, las reglas en la sección 0 **override** la baseline enterprise. Ver `aios/policies/amx-revenue-accounting/policy.md` v2.0.

## 0. AMX override (aplica solo si policy = `amx-revenue-accounting`)

### 0.1 Compute prohibido

- **ECS** · PROHIBIDO · severity CRITICAL (retro Antonio 20-abr-2026). Alternativa: EKS o Lambda.
- **SES** · PROHIBIDO para email transaccional. Alternativa: relay interno AMX.
- **SNS para email** · PROHIBIDO. Solo permitido para eventos.

### 0.2 Arquitectura por Tier

| Tier | Arquitectura obligatoria | EC2 permitido |
|---|---|---|
| T0 · misión crítica | EKS o Serverless (Lambda) | ❌ |
| T1 · satelital crítica | EKS o Serverless (Lambda) | ❌ |
| T2 · operación normal | EC2 · EKS · Serverless | ✅ |

### 0.3 IAM roles

- **Prefijo obligatorio** `amx-r-*` · enforced por SCPs
- Validar con `aios.core.security_gate.check_role_prefix(role_name)` antes de release
- Dos roles principales por cuenta: **ATR** (YubiKey · privilegios extra) y **desarrollo** (estándar)
- Ninguno puede modificar KMS ni policies organizacionales

### 0.4 KMS

- **Una CMK por servicio** (sin compartir)
- Provisioning: GateOne portal autoservicio u AMX Chat Service Desk
- Requiere correo visto bueno líder AMX previo + captura adjunta
- Aplicar vía IaC (CloudFormation · CDK)

### 0.5 Networking

- VPC dedicada por cuenta AWS · CIDR coordinado con Diego Zarate
- Akamai al frente OBLIGATORIO para endpoints públicos (WAF + CDN + DNS)
- Zero Trust · meta fin de año 2026

### 0.6 Deployment

- AWS CodeDeploy + GitHub Actions (GitHub Enterprise · no GitLab · no on-prem)
- Golden Image / AMI custom AMX (no genéricas)
- Rollback obligatorio · phased 0% → 10% → 50% → 90% → 100% para MIGRATION

### 0.7 Escaneos CYBER · secuencia obligatoria

1. **WIZ** · AWS cloud posture
2. **Veracode** · static code analysis
3. **Prisma Cloud** · contenedores + compute
4. **Tenable** · IaC

Criterio aceptación: **prácticamente cero HIGH/CRITICAL**. Loop iterativo scan → fix → re-scan → approve.

### 0.8 Proceso tickets AWS

1. Líder AMX envía correo visto bueno previo
2. Ticket en GateOne (o AMX Chat Service Desk)
3. Captura del correo adjunta
4. SLA 24h laborales (cuenta AWS)
5. Respuesta vía correo con ID del recurso

---

## 1. Baseline enterprise (aplica si NO hay override AMX)

### Infrastructure as Code
- Use Terraform or CloudFormation for all infra
- Never create resources manually in console for production
- State files must be remote (S3 + DynamoDB lock)
- Tag all resources with project, environment, owner

### Compute
- ECS Fargate for containerized services (no EC2 management) · **⚠ NO VÁLIDO BAJO AMX · VER §0.1**
- Lambda for event-driven / serverless functions
- Auto-scaling configured for production services

### Database
- RDS for relational (PostgreSQL preferred)
- DynamoDB for key-value / high-throughput
- Automated backups enabled
- Multi-AZ for production

### Networking
- VPC with public/private subnets
- ALB for load balancing
- Security groups: least privilege
- No public DB access

### Security
- IAM roles with least privilege (no admin access) · **⚠ bajo AMX añadir prefijo `amx-r-*` · ver §0.3**
- Secrets in AWS Secrets Manager or Parameter Store
- Encryption at rest and in transit
- CloudTrail enabled

### Deployment
- Use ECS rolling deploy or Blue/Green · **⚠ ECS no válido bajo AMX**
- Health checks on ALB target groups
- CloudWatch logs and alarms
- Rollback on failed health check

### Cost
- Use free tier where possible for dev/staging
- Monitor costs with AWS Budgets
- Right-size instances
- Spot instances for non-critical workloads
