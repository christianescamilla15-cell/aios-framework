# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/); versiones [SemVer](https://semver.org/lang/es/).

## [4.0.0] · 2026-11-24 · primera versión pública

Historia nueva a partir del árbol de la 3.8.2. Las reglas de organización pasan a ser datos de una
organización ficticia (Acme Corp) y se quita lo que sólo describía un despliegue concreto.

### Cambios respecto de la serie 3.x (uso interno, no publicada)
- Identificadores de reglas neutros: `AWS-*` (buenas prácticas de AWS/CDK), `ORG-*` (política de
  organización de ejemplo) o el del lenguaje (`DOTNET-*`, `ASPNET-*`, `FRONTEND-*`, `VBNET-*`).
- Las reglas de organización (TIER, nombres, firmas, interesados, catálogo, portafolio) son datos de
  ejemplo de una organización ficticia; el enrutamiento de escalamiento sale de `approvals.yaml`.
- `ORG-SERVICE-PROHIBITED` marca servicios AWS en retiro (OpsWorks, SimpleDB, Lightsail) como ejemplo.
- Se retiran dos comandos que no funcionaban fuera de un despliegue concreto.
- `requires-python >= 3.11` (3.10 quedó sin soporte en octubre de 2026); el CI prueba 3.11, 3.12 y 3.13.
- Los identificadores derivados (`FRK-…` de revisiones, huellas de caracterización, llaves de caché del
  clasificador, sufijo de specs largas) pasan de SHA-1 a SHA-256.

### Arreglado (detectores)
- 4 detectores multilínea (`^\s*`) cruzaban la línea anterior: tras un comentario el hallazgo se perdía y
  tras una línea en blanco se reportaba en la línea equivocada.
- El umbral de RTO de las reglas T0 se lee de `tiers.yaml` (antes 10 y 15 minutos fijos e incoherentes).
- Los detectores de buildspec ya no exigen una zona horaria concreta: basta con declarar `TZ`.

### Arreglado (CLI)
- `main()` descartaba el código que devuelven `aios governance …` y `aios tier …`: el proceso salía con 0
  aunque una transición se rechazara o la app no existiera. Ahora el código llega al proceso.
- `aios release` sale con 1 cuando no está listo (antes imprimía «Ready for release: NO» y salía con 0).

### Seguridad
- Extensión de VS Code: la CLI se invoca con `execFile` y argumentos en arreglo; antes el texto del
  usuario pasaba por el shell (CWE-78).
- XML de terceros (cobertura, `.config` del repo escaneado) con `defusedxml`: sin entidades ni DTD.
- URLs configurables (webhook de Slack, host de Ollama) sólo `http(s)`; los stacks se importan desde una
  lista blanca.

### Empaquetado
- Dependencias declaradas (PyYAML, Jinja2, defusedxml; extras `mcp` y `pdf`) y reglas/plantillas dentro
  del wheel: instalado fuera del árbol, `aios governance` no encontraba sus YAML.

### Retirado
- Artefactos compilados (`dist/`, `.vsix`) del control de versiones.
