#!/usr/bin/env bash
# Prueba de humo del paquete INSTALADO (no del árbol): versión esperada + comandos que leen datos del paquete.
# Uso: herramientas/humo.sh <ruta-al-ejecutable-aios> [versión-esperada]
set -euo pipefail
AIOS="${1:?uso: humo.sh <ruta-a-aios> [versión]}"
ESPERADA="${2:-}"
TRABAJO="$(mktemp -d)"
trap 'rm -rf "$TRABAJO"' EXIT
cd "$TRABAJO"

"$AIOS" version | tee version.txt
if [ -n "$ESPERADA" ]; then
  grep -q "v${ESPERADA}" version.txt || { echo "humo: se esperaba v${ESPERADA}"; exit 1; }
fi
"$AIOS" tier classify --app partners >/dev/null                       # tiers.yaml dentro del paquete
"$AIOS" governance check --app billing --root . >/dev/null             # naming.yaml + approvals.yaml
"$AIOS" governance request --type bd-access --app billing --format md --output ./req --audit-root . >/dev/null
ls req/*.md >/dev/null                                                 # plantillas Jinja2 dentro del paquete
echo "humo: OK"
