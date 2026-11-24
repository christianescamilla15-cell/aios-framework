# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/); versiones [SemVer](https://semver.org/lang/es/).

## [4.0.0] · 2026-11-24 · primera versión pública

Historia nueva a partir del árbol de la 3.8.2. Las reglas de organización pasan a ser datos de una
organización ficticia (Acme Corp) y se quita lo que sólo describía un despliegue concreto.

### Cambios incompatibles
- Identificadores de reglas: el prefijo de organización se reemplaza por `AWS-*` (buenas prácticas de
  AWS/CDK), `ORG-*` (política de organización de ejemplo) o el del lenguaje (`DOTNET-*`, `ASPNET-*`,
  `FRONTEND-*`, `VBNET-*`). Las supresiones con los identificadores viejos dejan de aplicar.
- `ORG-SERVICE-PROHIBITED` ahora marca servicios AWS en retiro (OpsWorks, SimpleDB, Lightsail) como
  ejemplo de política.
- CLI: `acme-catalog` / `acme-analog` → `org-catalog` / `org-analog`; se retiran `check-compliance` y
  `scaffold-deploy-ready` (este último importaba un módulo que nunca estuvo en el repositorio).
- Paquete de gobierno: los YAML describen a la organización ficticia; los tipos de solicitud
  `yubikey-request` y `dl-inclusion` pasan a `hardware-key` y `mailing-list`; `--to` de
  `governance escalate` acepta las llaves de `approvals.yaml` y el enrutamiento por severidad sale del YAML.
- `aios.core.plan_v5` → `aios.core.portfolio`; `aios.core.acme_catalog` → `aios.core.org_catalog`.
- `requires-python >= 3.11` (3.10 quedó sin soporte en octubre de 2026); el CI prueba 3.11, 3.12 y 3.13.
- Los identificadores derivados (`FRK-…` de revisiones, huellas de caracterización, llaves de caché del
  clasificador, sufijo de specs largas) pasan de SHA-1 a SHA-256: los de corridas previas no coinciden.

### Seguridad
- Extensión de VS Code: la CLI se invoca con `execFile` y argumentos en arreglo; antes el texto del
  usuario pasaba por el shell (CWE-78).
- XML de terceros (cobertura, `.config` del repo escaneado) con `defusedxml`: sin entidades ni DTD.
- URLs configurables (webhook de Slack, host de Ollama) sólo `http(s)`; los stacks se importan desde una
  lista blanca.

### Empaquetado
- Dependencias declaradas (PyYAML, Jinja2, defusedxml; extras `mcp` y `pdf`) y reglas/plantillas dentro
  del wheel: instalado fuera del árbol, `aios governance` no encontraba sus YAML.

### Arreglado
- El umbral de RTO de las reglas T0 se lee de `tiers.yaml` (antes 10 y 15 minutos fijos e incoherentes
  entre el clasificador y el verificador).
- El verificador de nombres y el catálogo de la organización volvieron a funcionar (un renombre previo
  dejó imports y expresiones regulares desalineados; 2 pruebas fallaban y 19 no se recolectaban).
- Los detectores de buildspec ya no exigen una zona horaria concreta: basta con declarar `TZ`.

### Retirado
- Especificaciones, notas de memoria, backlog y documentos de pilotos de un despliegue concreto.
- Artefactos compilados (`dist/`, `.vsix`) del control de versiones.
