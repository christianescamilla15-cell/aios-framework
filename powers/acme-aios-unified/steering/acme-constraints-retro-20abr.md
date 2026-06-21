---
inclusion: always
amx_policy: acme-finance_operations
note: Retro arquitectos 20-abr · constraints críticos · carga siempre en workspaces ACME
---

# ACME · Constraints de arquitectura (retro 20-abr-2026)

Reglas obligatorias confirmadas por los arquitectos ACME en la retro del 20-abr-2026 (Antonio Hernández Oropeza + Pedro Emmanuel Abaonza · plus Israel Miguel González Sandoval · Alexis Martínez · Rigoberto Texmayer Gaona · Miguel Rachid).

## Servicios AWS · prohibiciones absolutas en México

| Servicio | Regla | Alternativa obligatoria |
|---|---|---|
| **ECS** | 🔴 PROHIBIDO | EKS (Kubernetes) si containers · complejidad operativa aceptada |
| **SES** | 🔴 PROHIBIDO | **Relay interno ACME** · para correos transaccionales y alertas |
| **SNS (para correos)** | 🔴 PROHIBIDO | **Relay interno ACME** · SNS solo permitido para eventos no-correo |
| **KMS** | Obligatorio custom · **UNA POR SERVICIO** | No compartir CMK entre servicios · tickets individuales |
| **Akamai** | Obligatorio al frente | WAF + CDN para apps expuestas a internet |

## Roles IAM

- Prefijo obligatorio: `acme-r-*`
- SCPs (Service Control Policies) bloquean roles sin prefijo
- Dos roles principales:
  - **ATR con YubiKey** · privilegios extras · no modifica KMS/policies organizacionales
  - **desarrollo** · típico · sin excepciones destructivas

## Secuencia obligatoria de escaneos CYBER

1. **WIZ** · AWS posture (cloud)
2. **Veracode** · análisis estático de código
3. **Prisma Cloud** · containers y cargas de cómputo
4. **Tenable** · infrastructure-as-code (CDK/CloudFormation)

Standard de aceptación: "prácticamente sin vulnerabilidades altas o críticas" · excepciones con correo justificado a Miguel Rachid → registro formal.

## Gates pre-producción · orden obligatorio

Saltar un gate = equipos parados ~1 mes antes del go-live (caso documentado Antonio).

1. **óptimo** · alta de proyecto (Carina · Daniel Miranda fuera)
2. **Diagramas C4 en LeanIX** · subir link · no archivo
3. **ADR** con opción A vs B comparativa
4. **Borde de Arquitectura** · aprobación multi-persona · Israel Miguel González Sandoval principal
5. **Cuenta AWS ACME** · 24h SLA · correo líder previo + captura al ticket
6. **Diego Zarate** · VPC + subnets (Gateway/pública/privada/datos)
7. **Tickets KMS** · una por servicio · vía GateOne o ACME Chat Service Desk
8. **Escaneos CYBER** · secuencia WIZ → Veracode → Prisma → Tenable
9. **Miguel Rachid** · gate final · Gerente Ciberseguridad ACME

Nota arquitectos eTrive: **el diseño va antes que los fierros**. No pedir cuenta AWS/VPC/KMS sin tener C4 + ADR + aprobación Borde Arq · evita KMS equivocadas y rework.

## Clasificación Tier por aplicativo

| Tier | Arquitectura permitida | Criterio |
|---|---|---|
| **T0** | EKS o Serverless · OBLIGATORIO | Misión crítica 24×7 · revenue direct |
| **T1** | EKS o Serverless · OBLIGATORIO | Apps satelitales críticas (FLEET_OPS_APP · ARC · BSP · etc.) |
| **T2** | EC2 · K8s · Serverless · flexible | Operación normal · menor criticidad |

Consultar documento TIERS en el **sitio Dynamo**. Acceso: **Edgar Castillo** + **Israel Miguel González Sandoval**.

## Plataformas ACME obligatorias

| Plataforma | Uso |
|---|---|
| **óptimo** | Registro proyecto · prerequisito LeanIX |
| **LeanIX** | Diagramas C4 formales · CYBER pide link |
| **GitHub Enterprise** | Único repo código permitido · NO GitLab · NO Miatech on-prem |
| **GateOne** | Portal autoservicio tickets (KMS · AWS · Akamai) |
| **ACME Chat Service Desk** | Alternativa a GateOne |
| **ServiceNow CMDB** | Jira Traceability cerrando el ciclo commit→release |
| **Dynamo** | Documentación madurez + TIERS |

## Proceso ticket ACME (aplica a todo)

1. Líder ACME directo envía correo previo con visto bueno
2. Se levanta el ticket en GateOne (o ACME Chat Service Desk)
3. **Adjuntar captura del correo** como evidencia
4. SLA cuenta AWS: 24h laborales
5. Respuesta vía correo con ID del recurso (KMS · cuenta · etc.)

## Detectores AIOS relevantes

Cuando un aplicativo tenga el policy `acme-finance_operations` activo · AIOS aplica automáticamente estos detectores:

| Situación | Detector AIOS |
|---|---|
| Config con ECS reference | Advierte · señalar alternativa EKS/Serverless |
| Código con `SESSendEmail` / SNS para correos | Advierte · señalar Relay ACME |
| Hardcoded AWS KMS key shared | Advierte · CWE-798 + regla ACME |
| Role sin prefijo `acme-r-*` | Advierte · SCP violation |
| Secretos en config | CWE-522 (Sprint 5.2) + regla ACME |

## Referencia

- Transcripción 20-abr-2026 `2026-04-20 11-18-05.txt` · retro Antonio
- Imágenes 111118-111755.png · chat Antonio
- Captura GateOne dashboard (unnamed.webp)
- Sesión Ciber/Madurez 13:03 · Alexis explicando madurez
- Sesión Ciber/Madurez 13:31 · Rigo + Lalo + Lira + Ibrahim
- Sesión cierre 13:58 · Kiro + TIERS + Edgar Castillo
