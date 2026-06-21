# Tasks — ATOS-NOSHOW-ROBOT Modernización .NET 8 LTS

> Formato: `- [ ] N. Título · Req X.Y · Design §Z`
> 🚫 BLOCKER = depende de aprobación externa (gate ACME)

---

## Phase 1 · Setup — Solución y proyectos base

- [ ] 1.1. Crear solución `NoShow.sln` con estructura de carpetas `src/` y `tests/` · Req 9.3 · Design §Components
- [ ] 1.2. Crear proyecto `NoShow.Core` (.NET 8 · Class Library) con `<Nullable>enable</Nullable>` y `<ImplicitUsings>enable</ImplicitUsings>` · Req 9.3 · Design §Components
- [ ] 1.3. Crear proyecto `NoShow.Infrastructure` (.NET 8 · Class Library) con referencia a `NoShow.Core` · Req 9.3 · Design §Components
- [ ] 1.4. Crear proyecto `NoShow.FileGeneration` (.NET 8 · Class Library) con referencia a `NoShow.Core` · Req 5 · Design §Components
- [ ] 1.5. Crear proyecto `NoShow.Worker` (.NET 8 · Worker Service) con referencias a `NoShow.Core`, `NoShow.Infrastructure`, `NoShow.FileGeneration` · Req 9.3 · Design §Components
- [ ] 1.6. Crear proyecto `NoShow.Core.Tests` (xUnit · .NET 8) con referencia a `NoShow.Core` y paquetes `xunit`, `FsCheck.Xunit`, `coverlet.collector` · Req 9.3 · Design §Testing
- [ ] 1.7. Crear proyecto `NoShow.Integration.Tests` (xUnit · .NET 8) con paquetes `Testcontainers.MsSql`, `Testcontainers.Sftp`, `WireMock.Net` · Design §Testing
- [ ] 1.8. Agregar `NoshowConstants.cs` en `NoShow.Core/` con todas las constantes de negocio (AirlineCode, ExcludedStatuses, OutOfScopePrefixes, rutas SFTP, SmtpHost, etc.) · Req 5.4 · Design §Data Models
- [ ] 1.9. Agregar `.editorconfig` y `Directory.Build.props` con `TreatWarningsAsErrors=true` y `Nullable=enable` en la raíz de la solución · Design §Components
- [ ] 1.10. Agregar `global.json` fijando `sdk.version` a la versión .NET 8 LTS instalada · Req 9.3 · Design §Deployment

---

## Phase 2 · Core — Modelos de dominio e interfaces

- [ ] 2.1. Crear `FlightRecord.cs` en `NoShow.Core/Models/` como `sealed record` con propiedad `IsValid` (FlightNumber no nulo/vacío) · Req 14.3 · Design §Data Models
- [ ] 2.2. Crear `PassengerRecord.cs` en `NoShow.Core/Models/` con campos PII marcados en comentarios XML (`/// PII`) · Req 10 · Design §Data Models
- [ ] 2.3. Crear `TicketRecord.cs` en `NoShow.Core/Models/` con lista `Emds` y propiedad `IsValid` · Req 4 · Design §Data Models
- [ ] 2.4. Crear `EmdRecord.cs` en `NoShow.Core/Models/` · Req 4.4 · Design §Data Models
- [ ] 2.5. Crear `DateRange.cs` en `NoShow.Core/Models/` como `sealed record(DateTime Start, DateTime End)` con propiedad `IsValid` (Start ≤ End) · Req 1.2 · Design §Data Models
- [ ] 2.6. Crear `ReportResult.cs` en `NoShow.Core/Models/` · Req 5 · Design §Data Models
- [ ] 2.7. Crear interfaz `IFlightService.cs` en `NoShow.Core/Services/` · Req 2 · Design §Interfaces
- [ ] 2.8. Crear interfaz `ISabreService.cs` en `NoShow.Core/Services/` con métodos `GetPassengersAsync` y `EnrichWithTicketsAsync` · Req 3 · Design §Interfaces
- [ ] 2.9. Crear interfaz `IReportService.cs` en `NoShow.Core/Services/` · Req 5 · Design §Interfaces
- [ ] 2.10. Crear interfaz `INotificationService.cs` en `NoShow.Core/Services/` con métodos `SendAlertAsync` y `SendSuccessAsync` · Req 7 · Design §Interfaces
- [ ] 2.11. Crear interfaz `ISecretsProvider.cs` en `NoShow.Infrastructure/Secrets/` con los 4 métodos de credenciales · Req 8 · Design §Secrets Strategy
- [ ] 2.12. Crear modelos de configuración de secretos: `SabreCredentials`, `SftpCredentials`, `DbConnectionConfig`, `EmailConfig` en `NoShow.Infrastructure/Secrets/Models/` · Req 8.3 · Design §Data Models

---

## Phase 3 · Infrastructure — Implementaciones de infraestructura

### 3a · Secrets Manager

- [ ] 3.1. Agregar paquete NuGet `AWSSDK.SecretsManager` (versión exacta) a `NoShow.Infrastructure` · Req 8 · Design §Secrets Strategy
- [ ] 3.2. Implementar `SecretsManagerProvider.cs` en `NoShow.Infrastructure/Secrets/` con cache `ConcurrentDictionary` TTL 15 min y log de auditoría (nombre del secreto, no valor) · Req 8.4 · Design §Secrets Strategy
- [ ] 3.3. Implementar método `GetCachedSecretAsync<T>` con deserialización JSON y refresco automático al expirar · Req 8.4 · Design §Secrets Strategy
- [ ] 3.4. Implementar arranque defensivo: si Secrets Manager no responde al inicio → `IHostApplicationLifetime.StopApplication()` + log FATAL + exit code 1 · Req 8.5 · Design §Error Handling

### 3b · Base de datos AIDX

- [ ] 3.5. Agregar paquete NuGet `Dapper` y `Microsoft.Data.SqlClient` (versiones exactas) a `NoShow.Infrastructure` · Req 2 · Design §Components
- [ ] 3.6. Implementar `FlightRepository.cs` en `NoShow.Infrastructure/Data/` con query SQL parametrizado (sin interpolación de strings) y filtro de 49h · Req 2.1 · Design §Data Models
- [ ] 3.7. Implementar retry policy Polly para conexión a AIDX_DB: 3 intentos, backoff 5/15/30s · Req 2.4 · Design §Error Handling
- [ ] 3.8. Implementar `using` correcto en `SqlConnection` (IDisposable) — eliminar patrón legacy sin `using` · Req 2 · Design §Overview (hallazgos)

### 3c · SABRE API

- [ ] 3.9. Agregar referencias a los DLLs SOAP existentes (`CreateSession.dll`, `GetPassengerList.dll`, `GetReservation.dll`, `TicketingDocumentServicesRQ.dll`) desde `libs/` · Req 3 · Design §Components
- [ ] 3.10. Implementar `SabreSessionManager.cs` en `NoShow.Infrastructure/Sabre/` con gestión de token: crear sesión, detectar expiración por mensaje `"Expired"`, renovar y reintentar · Req 3.2 · Design §Interfaces
- [ ] 3.11. Implementar `SabreClient.cs` en `NoShow.Infrastructure/Sabre/` con método `GetPassengersAsync` usando `HttpClient` con `Timeout = 30s` · Req 3.1 · Design §Error Handling
- [ ] 3.12. Implementar `GetReservationAsync` y `GetTicketingDocumentAsync` en `SabreClient.cs` · Req 4.1 · Design §Interfaces
- [ ] 3.13. Implementar retry policy Polly para SABRE: 3 intentos, backoff 2/5/10s · Req 3.5 · Design §Error Handling
- [ ] 3.14. Implementar circuit breaker Polly para SABRE: threshold 5 fallas consecutivas, break 30s · Design §Error Handling
- [ ] 3.15. Implementar `ExceptionSanitizer.cs` en `NoShow.Infrastructure/Resilience/` con regex para remover `securityToken` de stacktraces antes de loggear · Req 10.6 · Design §Error Handling

### 3d · SFTP

- [ ] 3.16. Agregar paquete NuGet `SSH.NET` (versión exacta) a `NoShow.Infrastructure` · Req 6 · Design §ADR-003
- [ ] 3.17. Implementar `SftpUploader.cs` en `NoShow.Infrastructure/Sftp/` con buffer 4096 bytes, puerto 22, credenciales desde `ISecretsProvider` · Req 6.1 · Design §Interfaces
- [ ] 3.18. Implementar lógica de ruta dinámica en `SftpUploader`: `/CADUCOS` en modo PRODUCTION, `/CADUCOS/VALIDATION` en modo DUAL_RUN · Req 13.2 · Design §Migration Strategy
- [ ] 3.19. Implementar fallback SFTP: si falla tras retries → lanzar `SftpUploadException` custom para que el pipeline la capture y termine con exit code 1 · Design §Error Handling

### 3e · Email

- [ ] 3.20. Agregar paquetes NuGet `MailKit` y `MimeKit` (versiones exactas) a `NoShow.Infrastructure` · Req 7 · Design §ADR-004
- [ ] 3.21. Implementar `MailKitEmailSender.cs` en `NoShow.Infrastructure/Email/` con conexión a AMX_Relay `172.18.60.227:25` sin autenticación · Req 7.1 · Design §Interfaces
- [ ] 3.22. Implementar lectura de destinatarios desde `ISecretsProvider.GetEmailConfigAsync()` — eliminar hardcoding de 13 destinatarios · Req 7.2 · Design §Secrets Strategy
- [ ] 3.23. Implementar reemplazo de tokens `@fechaInicio`, `@fechaFin`, `@fecha` en plantilla HTML antes del envío · Req 7.7 · Design §Interfaces
- [ ] 3.24. Implementar `NullNotificationService.cs` en `NoShow.Infrastructure/Email/` para modo `--dry-run` (no envía correos) · Design §Testing

### 3f · Observability

- [ ] 3.25. Agregar paquetes NuGet `Serilog.AspNetCore`, `Serilog.Formatting.Compact`, `Serilog.Enrichers.Context` a `NoShow.Worker` · Design §Observability
- [ ] 3.26. Configurar Serilog en `Program.cs` con sink JSON a stdout, enrichers `CorrelationId`, `ProcessingDate`, `Environment` · Req 10.4 · Design §Observability
- [ ] 3.27. Implementar `CloudWatchMetricsPublisher.cs` en `NoShow.Infrastructure/Observability/` con métricas `NoShowRecordsProcessed`, `SabreCallsTotal`, `SabreCallsFailed`, `SftpUploadDurationMs`, `CycleDurationMs` · Design §Observability
- [ ] 3.28. Reemplazar todos los `Console.WriteLine` del código legacy migrado por llamadas a `ILogger<T>` (18 ocurrencias) · Req 10.4 · Design §Overview (hallazgos)

---

## Phase 4 · Worker + Pipeline — Orquestación del ciclo

- [ ] 4.1. Implementar `ReportLineFormatter.cs` en `NoShow.FileGeneration/` con formato pipe-delimited de 24 columnas · Req 5.3 · Design §Data Models
- [ ] 4.2. Implementar `ReportBuilder.cs` en `NoShow.FileGeneration/` con: línea H, línea de cabecera de columnas, registros D filtrados por status y prefijos, actualización de `totalRegistros` al final · Req 5.2 · Design §Components
- [ ] 4.3. Implementar filtro de statuses excluidos (`USED`, `VOID`, `EXCH`, `RFND`) y prefijos `OUTOFSCOPE_PREFIXES` en `ReportBuilder` · Req 5.4 · Design §Data Models
- [ ] 4.4. Implementar `PassengerFilter.cs` en `NoShow.Core/` con lógica de exclusión de pasajeros con `PNRLocator == null` · Req 3.3 · Design §Interfaces
- [ ] 4.5. Implementar `PiiMaskingService.cs` en `NoShow.Core/` con métodos: `MaskPnr` (`***AB`), `MaskName` (`J.***`), `MaskTicket` (`***1234`) · Req 10.1 · Design §Error Handling
- [ ] 4.6. Implementar `NoshowPipeline.cs` en `NoShow.Core/Pipeline/` como orquestador del ciclo completo: DB → SABRE → File → SFTP → Email, con `correlationId` UUID v4 inyectado en `LogContext` · Req 12.5 · Design §Architecture
- [ ] 4.7. Implementar lógica de modo `DUAL_RUN` en `NoshowPipeline`: comparar conteo de registros D vs legacy, registrar diff en log de auditoría, enviar alerta si diff > 2% en 3 ejecuciones consecutivas · Req 13.3 · Design §Migration Strategy
- [ ] 4.8. Implementar lógica de modo `--dry-run` en `NoshowPipeline`: usar `NullNotificationService`, escribir en `/CADUCOS/VALIDATION`, no enviar correos · Design §Testing
- [ ] 4.9. Eliminar vuelo `829` y fecha `2026-02-19` hardcoded de `MainServices.cs:57` — usar datos reales de `IFlightService` · Req 14.1 · Design §Overview (hallazgos)
- [ ] 4.10. Corregir `Remove` en iteración de `MainServices.cs:87` — reescribir con snapshot `ToList()` antes de iterar · Req 5 · Design §Overview (hallazgos)
- [ ] 4.11. Implementar `Worker.cs` en `NoShow.Worker/` como `IHostedService` que ejecuta `NoshowPipeline` una vez y llama `IHostApplicationLifetime.StopApplication()` al terminar · Req 1 · Design §ADR-001
- [ ] 4.12. Configurar `Program.cs` en `NoShow.Worker/` con Generic Host, DI registration de todos los servicios, lectura de `NOSHOW_MODE` y `NOSHOW_OUTPUT_PATH` desde variables de entorno · Req 1.1 · Design §Components
- [ ] 4.13. Implementar log de auditoría en `NoshowPipeline`: inicio/fin del ciclo, accesos a Secrets Manager, transferencia SFTP, envío de correo — todos con `correlationId` · Req 12.1 · Design §Architecture

---

## Phase 5 · Tests — Unitarios, property-based e integración

> Las tareas de test TDD preceden a su tarea Phase 4 correspondiente donde aplica.

- [ ] 5.1. Escribir tests unitarios para `PiiMaskingService`: PNR → `***AB`, nombre → `J.***`, ticket → `***1234`, string vacío, null · Req 10.1 · Design §Testing *(precede 4.5)*
- [ ] 5.2. Escribir tests unitarios para `PassengerFilter`: excluye PNRLocator null, incluye pasajeros válidos, lista vacía · Req 3.3 · Design §Testing *(precede 4.4)*
- [ ] 5.3. Escribir tests unitarios para `ReportLineFormatter`: 24 columnas, separador pipe, valores nulos → string vacío · Req 5.3 · Design §Testing *(precede 4.1)*
- [ ] 5.4. Escribir tests unitarios para `ReportBuilder`: línea H con conteo correcto, excluye USED/VOID/EXCH/RFND, excluye prefijos 139047/139048/139049, no sobreescribe archivo existente, actualiza totalRegistros · Req 5.4 · Design §Testing *(precede 4.2)*
- [ ] 5.5. Escribir property-based tests (FsCheck) para `FlightRecord.IsValid`: para todo `string flightNumber`, `IsValid ↔ !IsNullOrWhiteSpace(flightNumber)` · Req 14.3 · Design §Testing *(precede 2.1)*
- [ ] 5.6. Escribir property-based tests (FsCheck) para `DateRange.IsValid`: para todo par `(DateTime start, DateTime end)`, `IsValid ↔ start <= end` · Req 1.2 · Design §Testing *(precede 2.5)*
- [ ] 5.7. Escribir tests unitarios para `ExceptionSanitizer`: remueve `securityToken="abc123"`, remueve `<securityToken>abc</securityToken>`, preserva el resto del mensaje · Req 10.6 · Design §Testing *(precede 3.15)*
- [ ] 5.8. Escribir tests unitarios para `SecretsManagerProvider`: cache hit no llama AWS SDK, cache miss llama SDK, expiración de TTL fuerza refresco · Req 8.4 · Design §Testing *(precede 3.2)*
- [ ] 5.9. Escribir integration test para `FlightRepository` contra Testcontainers SQL Server: query parametrizado retorna vuelos del rango correcto, filtro 49h excluye vuelos antiguos · Req 2.1 · Design §Testing *(precede 3.6)*
- [ ] 5.10. Escribir integration test para `SabreClient` contra WireMock.Net: `GetPassengerList` retorna lista correcta, token expirado dispara renovación y reintento, retry policy se activa ante error 500 · Req 3.2 · Design §Testing *(precede 3.11)*
- [ ] 5.11. Escribir integration test para `SftpUploader` contra Testcontainers OpenSSH (`atmoz/sftp`): upload exitoso a `/CADUCOS`, fallo de conexión lanza `SftpUploadException`, buffer 4096 bytes · Req 6.1 · Design §Testing *(precede 3.17)*
- [ ] 5.12. Configurar Coverlet en `NoShow.Core.Tests` y agregar target `dotnet test --collect:"XPlat Code Coverage"` en CI — verificar cobertura ≥ 80% en `NoShow.Core` · Design §Testing
- [ ] 5.13. Escribir smoke test `--dry-run`: ejecutar `NoShow.Worker.dll --dry-run` contra entorno de staging, verificar que genera archivo en `/CADUCOS/VALIDATION` y no envía correos · Design §Testing

---

## Phase 6 · Deployment — Contenedor, K8s y CI/CD

- [ ] 6.1. Crear `Dockerfile` multi-stage en la raíz de la solución: stage `build` con `mcr.microsoft.com/dotnet/sdk:8.0`, stage `runtime` con `mcr.microsoft.com/dotnet/runtime:8.0` (Linux), usuario no-root `noshow` · Req 9.3 · Design §Deployment
- [ ] 6.2. Crear `infra/k8s/noshow-cronjob.yaml` con: `schedule: "50 6 * * *"`, `concurrencyPolicy: Forbid`, `startingDeadlineSeconds: 600`, `successfulJobsHistoryLimit: 3`, `failedJobsHistoryLimit: 5`, `backoffLimit: 3`, `restartPolicy: OnFailure`, resources requests `512Mi/500m`, limits `2Gi/1000m` · Req 9.4 · Design §Deployment
- [ ] 6.3. Crear `infra/k8s/noshow-serviceaccount.yaml` con anotación IRSA `eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/acme-r-noshow-execution` · Req 9.2 · Design §Deployment
- [ ] 6.4. Crear Helm chart en `infra/helm/noshow-robot/` con `Chart.yaml`, `values.yaml` (image tag, cron schedule, dual-run flag, log level), `values.prod.yaml`, templates `cronjob.yaml`, `serviceaccount.yaml`, `configmap.yaml` · Design §Deployment
- [ ] 6.5. Crear `infra/iam/acme-r-noshow-execution-policy.json` con permisos mínimos: `secretsmanager:GetSecretValue` sobre `noshow/*` y `kms:Decrypt` sobre `acme-noshow-cmk` · Req 8.6 · Design §Secrets Strategy
- [ ] 6.6. Crear `infra/cloudwatch/alarms.yaml` con alarmas: `noshow-sftp-failed`, `noshow-records-low` (< 500), `noshow-cycle-timeout` (> 90 min) · Design §Observability
- [ ] 6.7. Crear `infra/cloudwatch/dashboard.json` con widgets: latencia ciclo, throughput, error rate, last successful run timestamp · Design §Observability
- [ ] 6.8. Crear pipeline CI/CD en GitHub Enterprise (`.github/workflows/build-and-push.yml`): build → test → Veracode scan → docker build → push a ECR ACME → helm upgrade · Req 15.2 · Design §Deployment
- [ ] 6.9. Agregar `appsettings.json` en `NoShow.Worker/` con configuración no-sensible (cron, paths, timeouts, log level) — sin credenciales · Req 8.1 · Design §Components

---

## Phase 7 · Migration Dual-Run — Validación de paridad y cutover

- [ ] 7.1. Implementar `DualRunComparator.cs` en `NoShow.Core/Pipeline/` que compara conteo de registros D del nuevo sistema vs archivo legacy en `/CADUCOS` y registra diff en log de auditoría · Req 13.3 · Design §Migration Strategy
- [ ] 7.2. Implementar contador de ejecuciones consecutivas con diff > 2% en `DualRunComparator` — al llegar a 3, enviar alerta vía `INotificationService` y setear flag `CUTOVER_BLOCKED` · Req 13.4 · Design §Migration Strategy
- [ ] 7.3. Implementar lectura de `NOSHOW_MODE` en `NoshowPipeline`: `DUAL_RUN` → ruta `/CADUCOS/VALIDATION` + comparación; `PRODUCTION` → ruta `/CADUCOS` sin comparación · Req 13.5 · Design §Migration Strategy
- [ ] 7.4. Implementar lectura de `NOSHOW_CUTOVER` en `NoshowPipeline`: si `true` → forzar modo `PRODUCTION` sin redespliegue · Req 13.5 · Design §Migration Strategy
- [ ] 7.5. Escribir tests unitarios para `DualRunComparator`: diff < 2% no alerta, diff > 2% en 1 ejecución no alerta, diff > 2% en 3 consecutivas sí alerta · Req 13.4 · Design §Testing
- [ ] 7.6. Documentar procedimiento de rollback en `docs/runbook-rollback.md`: pasos para revertir `NOSHOW_MODE`, detener CronJob, retomar legacy · Design §Migration Strategy
- [ ] 7.7. Documentar exit criteria de cutover en `docs/cutover-checklist.md`: 10 ejecuciones con diff < 0.5%, sign-off Jacobo (Finance Operations), sign-off Víctor (líder ACME) · Design §Migration Strategy

---

## Phase 8 · ACME Gates — Pre-producción obligatorios (retro 20-abr-2026)

> 🚫 BLOCKER = requiere aprobación o acción de persona externa al equipo de desarrollo.
> Orden obligatorio: saltar un gate puede paralizar el equipo ~1 mes antes del go-live.

- [ ] 8.1. 🚫 BLOCKER · Dar de alta el proyecto en **óptimo** (Carina) — prerequisito para LeanIX · Req 15.1 · Design §ADR-005
- [ ] 8.2. 🚫 BLOCKER · Subir diagramas C4 (L1, L2, L3) a **LeanIX** y obtener link público — NO adjuntar archivo, subir link al ticket de Borde Arq · Req 15.3 · Design §Architecture
- [ ] 8.3. Registrar ADR-001 (Worker Service vs Console App) en el repositorio GitHub Enterprise bajo `docs/adr/` · Req 15.4 · Design §ADR-001
- [ ] 8.4. Registrar ADR-002 (Secrets Manager vs Parameter Store) en `docs/adr/` · Req 15.4 · Design §ADR-002
- [ ] 8.5. Registrar ADR-003 (SSH.NET vs WinSCP) en `docs/adr/` · Req 15.4 · Design §ADR-003
- [ ] 8.6. Registrar ADR-004 (MailKit vs SmtpClient) en `docs/adr/` · Req 15.4 · Design §ADR-004
- [ ] 8.7. Registrar ADR-005 (EKS CronJob vs Step Functions) en `docs/adr/` con comparativa opción A vs B · Req 15.4 · Design §ADR-005
- [ ] 8.8. 🚫 BLOCKER · Obtener aprobación de **Borde de Arquitectura** (Israel Miguel González Sandoval, aprobación multi-persona) — presentar link LeanIX + ADRs · Req 15.1 · Design §ADR-005
- [ ] 8.9. 🚫 BLOCKER · Enviar correo previo de Víctor (líder ACME) solicitando cuenta AWS, adjuntar captura al ticket · Req 15.1 · Design §Deployment
- [ ] 8.10. 🚫 BLOCKER · Levantar ticket de **cuenta AWS ACME** en GateOne (SLA 24h laborales) adjuntando captura del correo de Víctor · Req 15.1 · Design §Deployment
- [ ] 8.11. 🚫 BLOCKER · Coordinar con **Diego Zarate** la creación de VPC + subnets (Gateway / pública / privada / datos) para el cluster EKS · Req 15.1 · Design §Deployment
- [ ] 8.12. 🚫 BLOCKER · Levantar ticket KMS individual para `acme-noshow-cmk` vía **GateOne** o **ACME Chat Service Desk** — UNA CMK por servicio, no compartir · Req 15.5 · Design §Secrets Strategy
- [ ] 8.13. 🚫 BLOCKER · Ejecutar escaneo **WIZ** (postura AWS cloud) — sin vulnerabilidades altas/críticas sin excepción · Req 15.2 · Design §ADR-005
- [ ] 8.14. 🚫 BLOCKER · Ejecutar escaneo **Veracode** (análisis estático de código) sobre el repositorio GitHub Enterprise · Req 15.2 · Design §Deployment
- [ ] 8.15. 🚫 BLOCKER · Ejecutar escaneo **Prisma Cloud** (containers y cargas de cómputo) sobre la imagen Docker publicada en ECR · Req 15.2 · Design §Deployment
- [ ] 8.16. 🚫 BLOCKER · Ejecutar escaneo **Tenable** (infrastructure-as-code) sobre los manifests Helm/K8s en `infra/` · Req 15.2 · Design §Deployment
- [ ] 8.17. 🚫 BLOCKER · Obtener aprobación de **Miguel Rachid** (Gerente Ciberseguridad ACME) — gate final, requiere los 4 escaneos CYBER sin vulnerabilidades altas/críticas o con excepción formal por correo · Req 15.6 · Design §ADR-005

---

## Resumen de tareas por fase

| Fase | Tareas | Bloqueadores externos |
|---|---|---|
| Phase 1 · Setup | 10 | 0 |
| Phase 2 · Core | 12 | 0 |
| Phase 3 · Infrastructure | 28 | 0 |
| Phase 4 · Worker + Pipeline | 13 | 0 |
| Phase 5 · Tests | 13 | 0 |
| Phase 6 · Deployment | 9 | 0 |
| Phase 7 · Migration | 7 | 0 |
| Phase 8 · ACME Gates | 17 | 10 🚫 |
| **Total** | **109** | **10 🚫** |
