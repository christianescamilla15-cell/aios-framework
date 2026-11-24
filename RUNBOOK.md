# Runbook · aios-framework (Dowser)

AIOS es una **CLI y biblioteca de Python** más una **extensión de VS Code**. No hay servicio desplegado:
no corre en Vercel, Render ni en ninguna nube, y no se publica en PyPI ni en el Marketplace de VS Code. Lo
que se «entrega» es el paquete (wheel) y la extensión empaquetada (`.vsix`), ambos construidos desde `main`.

## Publicar una versión

1. Todo cambio entra por PR a `main` con los checks requeridos en verde (`ci`, `seguridad`).
2. Subir la versión en `pyproject.toml` y agregar la entrada en `CHANGELOG.md` (SemVer: un identificador de
   regla, un comando o un esquema de YAML que cambia es versión mayor).
3. Etiquetar: `git tag v<versión> && git push origin v<versión>`.
4. El job `paquete` de `ci` construye el wheel, lo instala en un entorno limpio fuera del árbol y corre
   `herramientas/humo.sh` contra el ejecutable instalado; el wheel queda como artefacto del run.

Instalación para usuarios: `pip install "git+https://github.com/christianescamilla15-cell/aios-framework.git@v<versión>"`.

### Extensión de VS Code

```bash
cd vscode-extension
npm ci && npm run compile          # lo mismo que corre el job `extension` del CI
npx vsce package                   # genera aios-vscode-<versión>.vsix (no se versiona: *.vsix en .gitignore)
code --install-extension aios-vscode-*.vsix
```

## Verificar una instalación

```bash
herramientas/humo.sh "$(command -v aios)" 4.0.0
```

Falla si la versión no coincide o si el paquete no encuentra sus datos (reglas YAML y plantillas).

## Revertir

No hay despliegue que revertir: se reinstala la etiqueta anterior y se verifica.

1. `pip install --force-reinstall "git+https://github.com/christianescamilla15-cell/aios-framework.git@v<anterior>"`
2. `herramientas/humo.sh "$(command -v aios)" <anterior>`

No ensayado todavía: 4.0.0 es la primera versión pública, no hay una anterior a la cual volver.

## Diagnóstico

| Síntoma | Causa probable | Qué hacer |
|---|---|---|
| `FileNotFoundError: Rule YAML missing` en `aios governance` | Paquete < 4.0.0: el wheel no incluía los YAML | Instalar ≥ 4.0.0 |
| `ModuleNotFoundError: mcp.server.fastmcp` al arrancar `aios-mcp` | `mcp` 2.x instalado (la API cambió) | `pip install "mcp>=1.2,<2"` o `pip install ".[mcp]"` |
| `aios-mcp: command not found` | Instalado sin el extra `mcp` o fuera del PATH | `pip install ".[mcp]"` y revisar el `bin` del entorno |
| Escaneo lento o cortado en archivos grandes | Tiempo máximo por regex | Subir `AIOS_REGEX_TIMEOUT_SECONDS` (por omisión 2) |
| `PDF: (skipped · weasyprint no disponible)` | Falta el extra `pdf` | `pip install ".[pdf]"` (requiere librerías de sistema de WeasyPrint) |
| `App '<x>' no soportada` en `aios governance` | La app no está en `tiers.yaml` o está `out_of_scope_*` | Agregarla a los cuatro YAML de `aios/governance/rules/` |
| Hallazgos que ya se revisaron vuelven a salir | Supresión vencida o con identificador viejo (< 4.0.0) | Revisar `aios-suppressions.json` (`expires_at`, `rule_id`) |
| El job `seguridad / semgrep` falla | Hallazgo nuevo de Semgrep | Corregir, o `nosemgrep: <regla> -- motivo` en la línea si es falso positivo |
