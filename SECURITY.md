# Seguridad

## Reportar una vulnerabilidad

Escribe a **christianescamilla15@gmail.com** con el asunto «Seguridad: aios-framework». Respondo en 72 horas
hábiles y publico el arreglo con su aviso. Por favor no abras un issue público para vulnerabilidades.

## Qué revisa cada cambio

| Revisión | Herramienta | Bloquea |
|---|---|---|
| Análisis estático | CodeQL (Python, JS/TS) + Semgrep `p/default` | sí (Semgrep) |
| Dependencias, configuración e IaC | Trivy | sí, en CRITICAL/HIGH con arreglo publicado |
| Secretos en toda la historia | gitleaks | sí |
| Datos de terceros | revisión de confidencialidad | sí |
| Inventario de componentes | SBOM (syft, SPDX) | no: se publica con cada versión |

Cada revisión debe probar que analizó algo (archivos o paquetes > 0); un reporte vacío cuenta como fallo.
Las excepciones viven en `.trivyignore` (con fecha de vencimiento y motivo), en `.gitleaks.toml` (por valor
exacto) y en el código como `nosemgrep: <regla> -- motivo`.

## Controles del propio producto

AIOS analiza código ajeno, así que trata su entrada como no confiable:

- **XML de terceros** (cobertura, `.config` del repo escaneado) con `defusedxml`: sin entidades ni DTD.
- **Expresiones regulares** con tiempo máximo por archivo (`AIOS_REGEX_TIMEOUT_SECONDS`) contra ReDoS.
- **URLs configurables** (webhook, host de Ollama) sólo `http(s)`; los stacks se importan de una lista blanca.
- **Extensión de VS Code**: la CLI se invoca con `execFile` y argumentos en arreglo, nunca por shell.
- **Hallazgos y reportes**: los valores de credenciales se redactan (drift, PII, literales prohibidos); el
  servidor MCP cuenta los literales prohibidos pero no los devuelve.
- **Bitácora de firmas** append-only encadenada por SHA-256 (`aios governance audit` detecta ediciones).
- Pruebas de regresión: `tests/test_endurecimiento.py`, `tests/test_kiro_integration.py`.

## Datos de ejemplo

Las reglas de organización del repositorio (TIER, nombres, firmas, catálogo) describen a una organización
ficticia (Acme Corp) con buzones del dominio reservado `.example`. El CI verifica con una lista de términos
(secreto `CONFIDENCIAL_TERMINOS`) que no entren datos de clientes reales.
