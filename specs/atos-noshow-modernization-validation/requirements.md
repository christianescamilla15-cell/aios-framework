# Requirements Document
# ATOS-NOSHOW-ROBOT · Modernización a .NET 8 LTS

## Introducción

El componente **ATOS-NOSHOW-ROBOT** es un servicio de misión crítica (Tier T1) que procesa
aproximadamente **1,350 no-shows por día** para Aeromexico Revenue Accounting. El sistema
consulta la base de datos AIDX para obtener vuelos del día anterior, interroga la API SOAP de
SABRE para obtener listas de pasajeros y documentos de ticketing, genera un archivo batch en
formato pipe-delimited y lo transfiere vía SFTP al servidor CADUCOS, además de enviar
notificaciones por correo electrónico.

El stack actual (.NET 4.7.2 · Windows Service · Quartz.NET) alcanza **EOL en enero 2026**,
lo que representa un riesgo de seguridad crítico. La modernización migra el componente a
**.NET 8 LTS** sobre infraestructura EKS (Tier T1 obligatorio), elimina las 6 credenciales
en texto plano migrándolas a **AWS Secrets Manager + KMS CMK custom**, y externaliza los
13 destinatarios de correo hardcoded al **Relay interno AMX** con configuración dinámica.

---

## Glosario

- **NoShow_Robot**: El sistema modernizado ATOS-NOSHOW-ROBOT en .NET 8.
- **AIDX_DB**: Base de datos SQL Server que contiene la tabla `flights` con datos operacionales de vuelos.
- **SABRE_API**: Sistema GDS externo accedido vía SOAP (SessionCreate · GetPassengerList · GetReservation · TicketingDocument).
- **SFTP_CADUCOS**: Servidor SFTP destino (`/CADUCOS`) donde se deposita el archivo batch diario.
- **AMX_Relay**: Servidor de correo interno AMX (`172.18.60.227:25`) — único mecanismo permitido para envío de correos (SES y SNS prohibidos).
- **Secrets_Manager**: AWS Secrets Manager con CMK KMS custom exclusiva del servicio (`amx-noshow-cmk`).
- **Report_File**: Archivo batch pipe-delimited (`yyyyMMdd.txt`) con registros de no-shows.
- **PNR**: Passenger Name Record — localizador de reserva en SABRE.
- **TKT**: Ticket electrónico de pasajero.
- **EMD**: Electronic Miscellaneous Document — documento anciliar asociado a un TKT.
- **RAC474**: Código de endoso de Revenue Accounting Aeromexico.
- **OUTOFSCOPE_PREFIXES**: Prefijos de ticket excluidos del reporte (`139047`, `139048`, `139049`).
- **Scheduler**: Componente de programación de ejecución (cron `0 50 6 1/1 * ? *` — 06:50 UTC diario).
- **EKS_Pod**: Unidad de despliegue Kubernetes en Amazon EKS (reemplaza Windows Service).
- **Dual_Run**: Período de ejecución paralela legacy + modernizado para validación de paridad.
- **CMK**: Customer Managed Key — clave KMS custom, una por servicio según constraint AMX.
- **IAM_Role**: Rol IAM con prefijo obligatorio `amx-r-*` según SCPs AMX.

---

## Requisitos

---

### Requisito 1: Ejecución Programada Diaria

**User Story:** Como equipo de Revenue Accounting, quiero que el NoShow_Robot se ejecute
automáticamente cada día a las 06:50 UTC, para que el reporte de no-shows del día anterior
esté disponible al inicio de la jornada operativa.

#### Criterios de Aceptación

1. THE NoShow_Robot SHALL ejecutarse según el cron `0 50 6 1/1 * ? *` (06:50 UTC diario) configurado externamente vía variable de entorno `NOSHOW_CRON`.
2. WHEN el Scheduler dispara la ejecución, THE NoShow_Robot SHALL procesar los vuelos del día anterior completo (00:00:00 a 23:59:59 hora local).
3. WHEN una ejecución está en curso, THE NoShow_Robot SHALL registrar en log estructurado el inicio, fin y duración total del ciclo.
4. IF el Scheduler no puede iniciar por error de configuración, THEN THE NoShow_Robot SHALL registrar el error con nivel FATAL y terminar el proceso con exit code distinto de cero.
5. THE NoShow_Robot SHALL completar el ciclo completo de procesamiento en un tiempo máximo de **90 minutos** desde el disparo del cron.

---

### Requisito 2: Consulta de Vuelos desde AIDX_DB

**User Story:** Como NoShow_Robot, quiero consultar la base de datos AIDX para obtener los
vuelos operados el día anterior, para determinar qué vuelos debo procesar.

#### Criterios de Aceptación

1. WHEN el ciclo de procesamiento inicia, THE NoShow_Robot SHALL consultar AIDX_DB con los parámetros de fecha inicio (`yyyy-MM-dd 00:00:00`) y fecha fin (`yyyy-MM-dd 23:59:59`) del día anterior.
2. THE NoShow_Robot SHALL filtrar únicamente vuelos cuyo `actual_take_off` tenga menos de **49 horas** de antigüedad respecto a `DateTime.UtcNow`.
3. WHEN AIDX_DB retorna cero vuelos para el rango de fechas, THE NoShow_Robot SHALL registrar una advertencia en log y finalizar el ciclo sin error.
4. IF la conexión a AIDX_DB falla, THEN THE NoShow_Robot SHALL reintentar la conexión hasta **3 veces** con backoff exponencial de 5, 15 y 30 segundos antes de abortar.
5. THE NoShow_Robot SHALL usar parámetros SQL parametrizados (no interpolación de strings) para todas las consultas a AIDX_DB.

---

### Requisito 3: Obtención de Lista de Pasajeros desde SABRE_API

**User Story:** Como NoShow_Robot, quiero consultar la API SABRE para obtener la lista de
pasajeros no-show por vuelo, para construir el reporte de Revenue Accounting.

#### Criterios de Aceptación

1. WHEN se procesa un vuelo, THE NoShow_Robot SHALL invocar `GetPassengerList` en SABRE_API con los parámetros: airline (`AM`), flightNumber, departure, flightDate y displayCode (`XON`).
2. WHEN SABRE_API retorna un token expirado (mensaje contiene `"Expired"`), THE NoShow_Robot SHALL renovar la sesión SABRE y reintentar la llamada original una vez.
3. WHEN un pasajero en la lista tiene `PNRLocator == null`, THE NoShow_Robot SHALL registrar el caso en log con nivel WARN y excluir al pasajero del procesamiento sin abortar el vuelo.
4. IF SABRE_API retorna `null` para `GetPassengerListRS`, THEN THE NoShow_Robot SHALL registrar advertencia y continuar con el siguiente vuelo.
5. THE NoShow_Robot SHALL implementar retry policy con **3 intentos** y backoff de 2, 5 y 10 segundos para todas las llamadas SOAP a SABRE_API.
6. THE NoShow_Robot SHALL registrar en log el total de pasajeros obtenidos por vuelo sin incluir nombres completos ni PNRs en texto plano (ver Requisito 10).

---

### Requisito 4: Obtención de Información de Reserva y Tickets

**User Story:** Como NoShow_Robot, quiero obtener los detalles de reserva y tickets electrónicos
de cada PNR, para incluir la información de ticketing en el reporte.

#### Criterios de Aceptación

1. WHEN se procesa un PNR, THE NoShow_Robot SHALL invocar `GetReservation` en SABRE_API para obtener los `ETicketNumber` asociados al PNR.
2. WHEN una reserva no contiene `TicketDetails`, THE NoShow_Robot SHALL registrar advertencia con el PNR (enmascarado) y continuar con el siguiente PNR.
3. THE NoShow_Robot SHALL invocar `TicketingDocument` en SABRE_API para cada número de ticket obtenido en el paso anterior.
4. WHEN un documento de ticketing corresponde a un EMD (no tiene `Ticket`, tiene `ElectronicMiscDocument`), THE NoShow_Robot SHALL procesarlo como EMD y asociarlo al TKT padre correspondiente.
5. WHEN un EMD tiene `EMDTipo != "S"` y `EMDEstatus != "USED"`, THE NoShow_Robot SHALL incluirlo como registro adicional en el Report_File.
6. IF `GetReservation` o `TicketingDocument` fallan con error no relacionado a token expirado, THEN THE NoShow_Robot SHALL registrar el error con PNR enmascarado y continuar con el siguiente PNR sin abortar el vuelo.

---

### Requisito 5: Generación del Report_File

**User Story:** Como equipo de Revenue Accounting, quiero recibir un archivo batch diario en
formato pipe-delimited con todos los no-shows procesados, para alimentar los sistemas de
contabilidad de ingresos.

#### Criterios de Aceptación

1. THE NoShow_Robot SHALL generar el Report_File con nombre `yyyyMMdd.txt` (fecha de ejecución) en la ruta configurada externamente vía variable de entorno `NOSHOW_OUTPUT_PATH`.
2. THE NoShow_Robot SHALL incluir una línea de encabezado tipo `H` con formato: `H|yyyy-MM-dd|{fechaInicio} {fechaFin}|{totalRegistros}`.
3. THE NoShow_Robot SHALL incluir una línea de cabecera de columnas: `TipoRegistro|consecutivo|stationNumber|pnr|saleDate|documentType|ticketNumber|couponNumber|passengerName|flightDate|flightNumber|marketingProvider|departure|arrival|itinerary|associatedFareBasis|fareRule|bookingClass|currentStatus|endosos|VCR_A|CP_VCR_A|ancilliariesCodes|ancilliariesSubCodes`.
4. THE NoShow_Robot SHALL incluir registros tipo `D` únicamente para tickets cuyo `currentStatus` NO esté en `{USED, VOID, EXCH, RFND}` y cuyo `couponNumber` no sea nulo.
5. THE NoShow_Robot SHALL excluir tickets cuyos primeros 6 dígitos del `ticketNumber` correspondan a OUTOFSCOPE_PREFIXES (`139047`, `139048`, `139049`).
6. WHEN el Report_File ya existe en la ruta destino, THE NoShow_Robot SHALL registrar advertencia y NO sobreescribir el archivo existente.
7. THE NoShow_Robot SHALL actualizar el contador `totalRegistros` en la línea `H` con el conteo real de registros `D` al finalizar el procesamiento.

---

### Requisito 6: Transferencia SFTP a CADUCOS

**User Story:** Como sistema CADUCOS, quiero recibir el Report_File vía SFTP cada día,
para procesar los no-shows en los sistemas downstream de Revenue.

#### Criterios de Aceptación

1. WHEN el Report_File ha sido generado exitosamente, THE NoShow_Robot SHALL transferirlo al SFTP_CADUCOS en el directorio `/CADUCOS` usando las credenciales obtenidas de Secrets_Manager.
2. THE NoShow_Robot SHALL usar puerto **22** para la conexión SFTP.
3. IF la conexión SFTP falla por `SocketException`, THEN THE NoShow_Robot SHALL registrar el error con nivel ERROR y enviar notificación de alerta vía AMX_Relay.
4. IF la ruta `/CADUCOS` no existe en el servidor SFTP, THEN THE NoShow_Robot SHALL registrar el error con nivel ERROR y enviar notificación de alerta vía AMX_Relay.
5. THE NoShow_Robot SHALL usar buffer de **4096 bytes** para la transferencia del archivo.
6. WHEN la transferencia SFTP se completa exitosamente, THE NoShow_Robot SHALL registrar confirmación en log con el nombre del archivo transferido.

---

### Requisito 7: Notificaciones por Correo Electrónico

**User Story:** Como equipo de Revenue Accounting, quiero recibir notificaciones por correo
cuando el proceso falla o completa exitosamente, para tener visibilidad del estado del robot.

#### Criterios de Aceptación

1. THE NoShow_Robot SHALL enviar correos exclusivamente a través de AMX_Relay (`172.18.60.227:25`) — el uso de AWS SES, AWS SNS o cualquier servicio externo de correo está PROHIBIDO.
2. THE NoShow_Robot SHALL leer la lista de destinatarios (`ToAddress`, `CCAddress`) desde Secrets_Manager en el path `noshow/email-config`, no desde código ni archivos de configuración estáticos.
3. WHEN el ciclo de procesamiento falla con excepción no controlada, THE NoShow_Robot SHALL enviar correo de alerta a los destinatarios configurados con el mensaje de error y stack trace.
4. THE NoShow_Robot SHALL usar la dirección remitente `amnoshow@aeromexico.com` con display name `AM No Show Report`.
5. THE NoShow_Robot SHALL usar el asunto `AM No Show Report` para todos los correos de notificación.
6. IF AMX_Relay no está disponible, THEN THE NoShow_Robot SHALL registrar el fallo de envío con nivel ERROR en log sin abortar el proceso principal.
7. WHERE el cuerpo del correo contiene plantilla HTML, THE NoShow_Robot SHALL reemplazar los tokens `@fechaInicio`, `@fechaFin` y `@fecha` con los valores del ciclo actual antes del envío.

---

### Requisito 8: Gestión de Credenciales con AWS Secrets Manager

**User Story:** Como equipo de Seguridad AMX, quiero que todas las credenciales del sistema
estén almacenadas en AWS Secrets Manager con CMK custom, para eliminar el riesgo CWE-522
(credenciales en texto plano) y cumplir con los controles SOX.

#### Criterios de Aceptación

1. THE NoShow_Robot SHALL obtener todas las credenciales en tiempo de ejecución desde Secrets_Manager — ninguna credencial SHALL existir en archivos de configuración, variables de entorno, código fuente ni imágenes de contenedor.
2. THE NoShow_Robot SHALL usar una CMK KMS exclusiva (`amx-noshow-cmk`) para cifrar los secretos — esta CMK NO SHALL ser compartida con ningún otro servicio.
3. THE Secrets_Manager SHALL almacenar los siguientes secretos bajo el prefijo `noshow/`:
   - `noshow/sabre-credentials` → `{ "username": "...", "password": "...", "ipcc": "AM", "subjectArea": "FULL" }`
   - `noshow/sftp-credentials` → `{ "host": "10.19.17.33", "port": 22, "username": "AMUSER", "passphrase": "..." }`
   - `noshow/db-connection` → `{ "server": "172.24.34.77", "database": "AIDX", "uid": "...", "password": "..." }`
   - `noshow/email-config` → `{ "toAddress": [...], "ccAddress": [...], "fromAddress": "amnoshow@aeromexico.com" }`
4. THE NoShow_Robot SHALL cachear los secretos en memoria por un máximo de **15 minutos** antes de refrescarlos desde Secrets_Manager para reducir latencia.
5. IF Secrets_Manager no está disponible al inicio, THEN THE NoShow_Robot SHALL abortar el arranque con exit code distinto de cero y registrar el error con nivel FATAL.
6. THE IAM_Role asignado al EKS_Pod SHALL tener prefijo `amx-r-*` y permisos mínimos: `secretsmanager:GetSecretValue` y `kms:Decrypt` únicamente sobre los ARNs de los secretos `noshow/*`.

---

### Requisito 9: Infraestructura EKS (Tier T1)

**User Story:** Como arquitecto AMX, quiero que el NoShow_Robot se despliegue en EKS
(no ECS, que está prohibido), para cumplir con los constraints de infraestructura Tier T1.

#### Criterios de Aceptación

1. THE NoShow_Robot SHALL desplegarse como EKS_Pod en Amazon EKS — el uso de Amazon ECS está PROHIBIDO por constraints AMX retro 20-abr.
2. THE EKS_Pod SHALL ejecutarse con el IAM_Role `amx-r-noshow-execution` que tenga únicamente los permisos mínimos necesarios.
3. THE NoShow_Robot SHALL empaquetarse como imagen de contenedor basada en `mcr.microsoft.com/dotnet/runtime:8.0` (imagen oficial .NET 8 LTS).
4. THE EKS_Pod SHALL usar un CronJob de Kubernetes con el schedule `50 6 * * *` para disparar la ejecución diaria.
5. THE EKS_Pod SHALL tener resource limits definidos: CPU máximo **500m**, memoria máxima **512Mi**.
6. WHERE el NoShow_Robot está expuesto a internet, THE sistema SHALL usar Akamai como edge obligatorio — para este componente (batch interno) Akamai no aplica al no tener endpoints HTTP públicos.
7. THE NoShow_Robot SHALL almacenar el código fuente exclusivamente en **GitHub Enterprise AMX** — GitLab y repositorios Miatech on-prem están PROHIBIDOS.

---

### Requisito 10: Seguridad de Logs y Protección de PII

**User Story:** Como equipo de Seguridad y Compliance AMX, quiero que los logs del sistema
no contengan información personal identificable (PII) ni credenciales, para cumplir con
controles SOX y políticas de privacidad.

#### Criterios de Aceptación

1. THE NoShow_Robot SHALL enmascarar los PNRs en todos los mensajes de log usando el patrón `***{últimos 2 caracteres}` (ej: `***AB`).
2. THE NoShow_Robot SHALL enmascarar los nombres de pasajeros en logs usando el patrón `{inicial}.***` (ej: `J.***`).
3. THE NoShow_Robot SHALL enmascarar los números de ticket en logs mostrando únicamente los últimos 4 dígitos (ej: `***1234`).
4. THE NoShow_Robot SHALL usar logging estructurado (JSON) compatible con el stack de observabilidad AMX — no Console.WriteLine.
5. THE NoShow_Robot SHALL registrar en log el nivel de severidad, timestamp ISO-8601, nombre del componente, correlationId del ciclo y el mensaje — sin incluir valores de credenciales.
6. IF un mensaje de excepción contiene una credencial o token de sesión SABRE, THEN THE NoShow_Robot SHALL sanitizar el mensaje antes de escribirlo en log.
7. THE NoShow_Robot SHALL retener logs locales por un máximo de **7 días** — la retención a largo plazo es responsabilidad del stack de observabilidad AMX.

---

### Requisito 11: SLA, RTO y RPO (Tier T1)

**User Story:** Como Director de Revenue Accounting, quiero que el sistema tenga SLAs
definidos y documentados, para garantizar la continuidad operativa del proceso de no-shows
que impacta directamente los ingresos de Aeromexico.

#### Criterios de Aceptación

1. THE NoShow_Robot SHALL tener disponibilidad objetivo de **99.5%** mensual (Tier T1 · apps satelitales críticas).
2. THE NoShow_Robot SHALL tener un RTO (Recovery Time Objective) máximo de **4 horas** ante fallo total del servicio.
3. THE NoShow_Robot SHALL tener un RPO (Recovery Point Objective) máximo de **24 horas** (un ciclo diario de procesamiento).
4. WHEN el ciclo diario no se ejecuta dentro de los **30 minutos** posteriores a la hora programada (07:20 UTC), THE NoShow_Robot SHALL generar una alerta automática vía AMX_Relay.
5. THE NoShow_Robot SHALL procesar un mínimo de **1,350 no-shows por día** sin degradación de rendimiento.
6. WHILE el sistema está en período de Dual_Run, THE NoShow_Robot SHALL completar el ciclo en paralelo con el sistema legacy sin interferir con la transferencia SFTP del sistema legacy.

---

### Requisito 12: Compliance SOX y Auditoría

**User Story:** Como equipo de Auditoría Interna AMX, quiero que el sistema genere trazas
de auditoría completas e inmutables, para cumplir con los controles SOX aplicables a
sistemas de Revenue Accounting.

#### Criterios de Aceptación

1. THE NoShow_Robot SHALL registrar en log de auditoría cada ejecución del ciclo con: timestamp inicio, timestamp fin, número de vuelos procesados, número de registros generados y resultado (SUCCESS/FAILURE).
2. THE NoShow_Robot SHALL registrar en log de auditoría cada acceso a Secrets_Manager con: timestamp, secreto accedido (nombre, no valor) y resultado.
3. THE NoShow_Robot SHALL registrar en log de auditoría cada transferencia SFTP con: timestamp, nombre de archivo, tamaño en bytes y resultado.
4. THE NoShow_Robot SHALL registrar en log de auditoría cada envío de correo con: timestamp, destinatarios (sin contenido del cuerpo) y resultado.
5. THE NoShow_Robot SHALL generar un correlationId único (UUID v4) por ciclo de ejecución que aparezca en todos los registros de log de ese ciclo.
6. THE NoShow_Robot SHALL conservar los logs de auditoría en formato inmutable — no deben ser modificables por el proceso mismo.

---

### Requisito 13: Estrategia de Migración Dual-Run

**User Story:** Como líder técnico, quiero ejecutar el sistema modernizado en paralelo con
el legacy durante un período de validación, para garantizar paridad de resultados antes
del cutover definitivo.

#### Criterios de Aceptación

1. THE NoShow_Robot SHALL soportar un modo `DUAL_RUN` activable vía variable de entorno `NOSHOW_MODE=DUAL_RUN` donde ambos sistemas (legacy .NET 4.7.2 y modernizado .NET 8) se ejecutan en paralelo.
2. WHILE el sistema está en modo `DUAL_RUN`, THE NoShow_Robot SHALL depositar el Report_File en una ruta SFTP alternativa (`/CADUCOS/VALIDATION`) sin interferir con la ruta de producción (`/CADUCOS`).
3. WHILE el sistema está en modo `DUAL_RUN`, THE NoShow_Robot SHALL comparar el conteo de registros `D` generados contra el sistema legacy y registrar las diferencias en log de auditoría.
4. WHEN la diferencia de registros entre el sistema modernizado y el legacy supera el **2%** en 3 ejecuciones consecutivas, THE NoShow_Robot SHALL enviar alerta automática al equipo técnico vía AMX_Relay.
5. THE NoShow_Robot SHALL soportar cutover mediante cambio de variable de entorno `NOSHOW_MODE=PRODUCTION` sin necesidad de redespliegue de imagen.
6. WHEN se activa el modo `PRODUCTION`, THE NoShow_Robot SHALL deshabilitar la escritura en la ruta de validación y usar exclusivamente la ruta de producción `/CADUCOS`.

---

### Requisito 14: Corrección del Vuelo Hardcoded (Hallazgo Crítico)

**User Story:** Como equipo de Revenue Accounting, quiero que el sistema procese los vuelos
reales del día anterior en lugar de un vuelo hardcoded, para que el reporte refleje la
operación real de Aeromexico.

#### Criterios de Aceptación

1. THE NoShow_Robot SHALL procesar todos los vuelos retornados por AIDX_DB para el rango de fechas del día anterior — el número de vuelo `829` y la fecha `2026-02-19` hardcoded en `MainServices.cs:57` SHALL ser eliminados.
2. THE NoShow_Robot SHALL usar el `flightNumber`, `flightDate`, `departure` y `arrival` provenientes de AIDX_DB para cada vuelo procesado.
3. WHEN AIDX_DB retorna un vuelo con `flightNumber` nulo o vacío, THE NoShow_Robot SHALL registrar advertencia y omitir ese vuelo del procesamiento.
4. THE NoShow_Robot SHALL registrar en log el número de vuelo y fecha de cada vuelo procesado usando el valor real de AIDX_DB.

---

### Requisito 15: Gates Pre-Producción AMX

**User Story:** Como arquitecto AMX, quiero que el proceso de release del sistema modernizado
siga los gates obligatorios definidos en la retro del 20-abr-2026, para garantizar el
cumplimiento de los estándares de gobernanza AMX antes del go-live.

#### Criterios de Aceptación

1. THE NoShow_Robot SHALL completar los siguientes gates en orden antes del despliegue a producción: óptimo → LeanIX C4 → ADR → Borde de Arquitectura → Cuenta AWS → Diego Zarate VPC → Tickets KMS → Escaneos CYBER → Miguel Rachid.
2. THE NoShow_Robot SHALL pasar la secuencia de escaneos CYBER en orden: **WIZ** (postura AWS) → **Veracode** (análisis estático) → **Prisma Cloud** (containers) → **Tenable** (IaC).
3. THE NoShow_Robot SHALL tener diagramas C4 publicados en **LeanIX** (link, no archivo adjunto) antes de solicitar aprobación de Borde de Arquitectura.
4. THE NoShow_Robot SHALL tener un ADR con comparativa opción A vs opción B documentado antes del gate de Borde de Arquitectura.
5. THE NoShow_Robot SHALL tener ticket KMS individual levantado vía GateOne o AMX Chat Service Desk para la CMK `amx-noshow-cmk` — no compartir CMK con otros servicios.
6. WHEN algún escaneo CYBER detecta vulnerabilidades altas o críticas, THE NoShow_Robot SHALL bloquear el gate de Miguel Rachid hasta que las vulnerabilidades sean remediadas o tengan excepción formal aprobada por correo a Miguel Rachid.

---

## Resumen de Hallazgos Críticos Incorporados

| Hallazgo | Severidad | Requisito que lo atiende |
|---|---|---|
| .NET 4.7.2 EOL enero-2026 | CRÍTICO | Req 9 (EKS + .NET 8) |
| Vuelo 829 hardcoded | CRÍTICO | Req 14 |
| 6 credenciales plaintext | CRÍTICO | Req 8 |
| Drift SABRE creds source↔prod | CRÍTICO | Req 8 (Secrets Manager) |
| ECS prohibido (AMX constraint) | BLOQUEADOR | Req 9 |
| SES/SNS prohibido (AMX constraint) | BLOQUEADOR | Req 7 |
| KMS compartida prohibida | BLOQUEADOR | Req 8 |
| Remove en iteración (MainServices.cs:87) | HIGH | Req 5 (generación correcta) |
| 0 tests · 0% XML-doc | HIGH | Req 3, 4, 5 (criterios testables) |
| IPs hardcoded (3 IPs) | HIGH | Req 8 (Secrets Manager) |
| SABRE sin retry policy (162 calls · 0 retry) | HIGH | Req 3, 4 |
| Console.WriteLine (18 ocurrencias) | MEDIUM | Req 10 (logging estructurado) |
| Exception genérico (14 ocurrencias) | MEDIUM | Req 3, 4, 6 |
| IDisposable sin using (3 casos) | MEDIUM | Req 2 (conexión DB) |
