# ADR 0002 · Detectores de seguridad por expresión regular, embebidos y con tiempo máximo

- Estado: aceptada · Fecha: 2026-11-24 (registra una decisión vigente desde la 1.7)

## Contexto
AIOS tiene que dar un primer barrido de seguridad sobre repositorios heredados heterogéneos (Python, C#,
VB.NET, Java, COBOL, PHP, JS/TS, configuración .NET, CDK/Terraform, buildspec) sin instalar nada y en
segundos, dentro de un hook de pre-commit o de la herramienta MCP que llama un agente.

## Decisión
- Los detectores viven en `aios/core/security_gate.py` como tuplas `(CWE, regex, regla, severidad,
  mensaje, extensiones)`: 123 reglas, cada una con su CWE.
- Antes de buscar se blanquean los comentarios conservando offsets; un hallazgo en una línea de comentario
  se descarta. Por eso los anclajes multilínea usan `^[ \t]*` y nunca `^\s*` (que cruza saltos de línea).
- Cada búsqueda corre con tiempo máximo (`AIOS_REGEX_TIMEOUT_SECONDS`, 2 s) para que un archivo patológico
  no cuelgue el escaneo (ReDoS).
- Las herramientas profundas (Semgrep, Trivy, Checkov, gitleaks…) se envuelven aparte (`*_scan.py`,
  `ensemble_scanner.py`) y son opcionales.
- Cada regla tiene un caso positivo y uno negativo en `tests/golden/detectores.json` o una prueba propia;
  `test_todo_detector_tiene_al_menos_una_prueba` lo exige.

## Alternativas
- *Sólo envolver Semgrep/CodeQL*: más preciso, pero exige instalación y tiempo, y no cubre VB.NET/COBOL.
- *Analizadores por AST por lenguaje*: precisión alta, costo de mantenimiento de 8+ parsers.

## Consecuencias
Rápido y sin dependencias, con falsos positivos que se gestionan con supresiones con vencimiento y con la
clasificación previa al auto-fix (`ontology.py`, `llm_classifier.py` y `review.py`). Un regex nuevo sin caso en el
oráculo hace fallar el CI.
