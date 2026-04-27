# AIOS Discovery · Guía de comandos

> Auto-generación de los 9 documentos estándar Fase 1 Discovery del plan v5 Revenue Accounting Aeroméxico.
>
> Destinatarios: consultores del equipo eTride con acceso al repo privado
> `chernandeze_amx/aios-framework`.

---

## 1 · Pre-requisitos (una vez por máquina)

```bash
python3 --version      # requerido: >= 3.10
git --version
ssh -T git@github.com  # verifica SSH config (o usa HTTPS + PAT)
```

---

## 2 · Instalación

```bash
# Clone (SSH recomendado)
git clone git@github.com:chernandeze_amx/aios-framework.git
cd aios-framework

# Virtual environment (recomendado · evita conflicto con otros proyectos Python)
python3 -m venv .venv
source .venv/bin/activate              # Linux / macOS / WSL
# Windows PowerShell: .\.venv\Scripts\Activate.ps1

# Install editable
pip install --upgrade pip
pip install -e .

# Verificar
aios version
# Esperado: AIOS v3.7.5 (o superior)
```

### Dependencias opcionales (solo si las usas)

| Feature | Package | Comando install |
|---|---|---|
| PDF generation (`--pdf` flag) | weasyprint | `pip install weasyprint` + libs sistema (ver troubleshooting) |
| Semgrep scan | semgrep | `pip install semgrep` |
| Trivy container scan | trivy (binario) | Linux: `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \| sh`<br>macOS: `brew install trivy` |
| Checkov IaC scan | checkov | `pip install checkov` |

---

## 3 · Comando principal · `aios discovery-generate`

### 3.1 · Uso básico

```bash
aios discovery-generate --app <nombre> --root <path>
```

Genera los 9 docs en `<root>/analisis/fase-1-discovery/`:

```
01_code_scan.md          findings AIOS por severidad + top CWEs
02_hallazgos_mapped.md   CWE mapping + placeholder assessment externo
03_arq_as_is.md          stack detectado + topología template
04_stakeholders.md       owners plan v5 + governance AMX completo
05_vulns.md              vulns detalle + compliance LFPDPPP/PCI/SOX/CFF
06_deps.md               lockfiles detectados + upgrade targets
07_preguntas_nuevas.md   6 categorías bloqueadoras + TOP 5
08_bloqueadores.md       CROSS_APP_BLOCKERS + matriz mitigación local
09_risk_register.md      riesgos por Tier + heurística findings AIOS
```

### 3.2 · Ejemplos concretos

```bash
# SICOFAV (T0 Mission Critical · SOX)
aios discovery-generate --app sicofav --root ~/apps/01-sicofav/refactor

# ARC (T1 Compliance)
aios discovery-generate --app arc --root ~/apps/02-arc

# Sobrescribir docs existentes (default: skip si existen)
aios discovery-generate --app sicofav --root ~/apps/01-sicofav/refactor --overwrite

# Output JSON para scripts / pipelines
aios discovery-generate --app sicofav --root ~/apps/01-sicofav --format json

# Con PDFs (v3.7.1+ · requiere weasyprint)
aios discovery-generate --app sicofav --root ~/apps/01-sicofav --pdf
# Genera también: fase-1-discovery/pdfs/01_code_scan.pdf ... 09_risk_register.pdf
```

### 3.3 · Apps disponibles del plan v5

| Key | App | Tier | Criticality |
|---|---|---|---|
| `sicofav` | SICOFAV | T0 | Mission Critical · SOX |
| `arc` | Reembolsos ARC | T1 | Compliance regulatorio |
| `bsp` | Reembolsos BSP | T1 | Compliance regulatorio |
| `cfdis` | Descarga CFDIs | T1 | Compliance regulatorio SAT |
| `srg` | SRG | T2 | Batch operativo |
| `noshow` | NoShow | T2 | Revenue recognition |
| `robot` | Robot Cálculo Venta Directa | T2 | Cálculo comercial |
| `asr` | ASR | T2 | Liquidaciones |
| `comisiones_directas` | Comisiones Directas | T3 | Operativo |
| `comisiones_indirectas` | Comisiones Indirectas | T3 | Operativo |

Para listar programáticamente:
```bash
python3 -c "from aios.core.plan_v5 import APPS; import json; print(json.dumps({k: v.tier for k,v in APPS.items()}, indent=2))"
```

### 3.4 · Flags completos

| Flag | Default | Descripción |
|---|---|---|
| `--app <name>` | (requerido) | Key del aplicativo del plan v5 |
| `--root <path>` | `.` (cwd) | Root del repo de la app (para scan + stack detect) |
| `--overwrite` | `False` | Sobrescribe docs existentes (default: skip) |
| `--pdf` | `False` | v3.7.1+ · genera también PDFs en `pdfs/` subfolder |
| `--format {human,json}` | `human` | Formato de salida del comando |

---

## 4 · Comandos relacionados (pre/post Discovery)

### 4.1 · Pre-Discovery · `aios scan`

Scan AIOS standalone (opcional · `discovery-generate` lo corre internamente):

```bash
aios scan --root ~/apps/01-sicofav/refactor
```

Devuelve findings por severidad CRITICAL/HIGH/MEDIUM/LOW/INFO.

### 4.2 · Post-Discovery · `aios phase1-report`

Consolida los 9 docs en un Evidence Bundle markdown (+ opcional PDF):

```bash
# Markdown solamente
aios phase1-report --app sicofav --root ~/apps/01-sicofav/refactor

# Markdown + PDF consolidado
aios phase1-report --app sicofav --root ~/apps/01-sicofav/refactor --pdf
```

Output: `<root>/analisis/fase-1-discovery/DISCOVERY_PACKAGE_<APP>.md` (+ `.pdf`)

### 4.3 · Compliance · `aios compliance-report`

Mapea findings → LFPDPPP / PCI-DSS / SOX / CFF / OWASP:

```bash
aios compliance-report --root ~/apps/01-sicofav/refactor
```

### 4.4 · Dependencias · `aios sbom` + `aios npm-audit`

```bash
# SBOM CycloneDX (Python o Node)
aios sbom --root ~/apps/01-sicofav/refactor --format cyclonedx

# Frontend (si la app tiene package.json)
aios npm-audit --root ~/apps/01-sicofav/refactor --fail-on high
```

### 4.5 · BO-AMX análogos · `aios amx-analog`

Sugiere repos BO-AMX análogos (plantillas / referencias):

```bash
aios amx-analog --root ~/apps/01-sicofav/refactor
```

### 4.6 · Ver todos los subcomandos disponibles

```bash
aios --help
# 47 subcomandos · help por cada uno con:
aios discovery-generate --help
aios phase1-report --help
# etc.
```

---

## 5 · Flujo end-to-end recomendado

```bash
# Navegar al repo de la app a analizar
cd ~/apps/01-sicofav/refactor

# 1. Generar los 9 docs Discovery (incluye scan internamente)
aios discovery-generate --app sicofav --root . --pdf

# 2. Revisar los 9 docs generados
ls analisis/fase-1-discovery/
code analisis/fase-1-discovery/03_arq_as_is.md  # o tu editor preferido

# 3. Completar los TODOs humanos en cada .md
#    (marcados como "**TODO humano**: ...")
#    Workshops, entrevistas con stakeholders, assessment externo, etc.

# 4. Re-generar PDFs después de editar (opcional)
aios discovery-generate --app sicofav --root . --overwrite --pdf

# 5. Consolidar en Evidence Bundle
aios phase1-report --app sicofav --root . --pdf

# 6. Commit al repo de la app (NO al de aios-framework)
cd ~/apps/01-sicofav
git add analisis/fase-1-discovery/
git commit -m "docs(discovery): cerrar Fase 1 Discovery · baseline SICOFAV"
```

---

## 6 · Troubleshooting

### `aios: command not found`

```bash
# Venv no activado O pip install no ejecutado
source .venv/bin/activate
pip install -e .
which aios     # debe apuntar a .venv/bin/aios
```

### `python3 --version` muestra 3.8 o 3.9

```bash
# Instalar Python 3.10+
# Ubuntu/Debian:
sudo apt update && sudo apt install -y python3.10 python3.10-venv
# macOS: brew install python@3.11
# Windows: descargar desde python.org (no Microsoft Store)
```

### `aplicativo 'xxx' no encontrado`

```bash
# Ver lista exacta (keys sensibles a guiones bajos vs guiones)
python3 -c "from aios.core.plan_v5 import APPS; print(sorted(APPS.keys()))"
```

### SSH clone falla con `Permission denied (publickey)`

```bash
# Verifica SSH key en GitHub
ssh -T git@github.com
# Si falla: genera SSH key + súbela a GitHub > Settings > SSH keys
ssh-keygen -t ed25519 -C "tu.email@etride.mx"
cat ~/.ssh/id_ed25519.pub  # copiar al clipboard + pegar en GitHub
```

### Clone con HTTPS + Personal Access Token

```bash
# Si SSH no es opción (red corporativa, firewall, etc.)
# GitHub > Settings > Developer settings > Personal access tokens > Fine-grained
# Scope: Read repository
git clone https://<username>:<token>@github.com/chernandeze_amx/aios-framework.git
```

### `weasyprint: command not found` al usar `--pdf`

```bash
# Linux (Ubuntu/Debian):
sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b \
  libcairo2 libcairo-gobject2 libgdk-pixbuf2.0-0 shared-mime-info
pip install weasyprint

# macOS:
brew install pango gdk-pixbuf libffi
pip install weasyprint

# Verificar:
weasyprint --version
```

### PDF se genera pero archivo corrupto / vacío

```bash
# Verifica weasyprint con sample simple
echo "<h1>test</h1>" | weasyprint - /tmp/test.pdf
# Si falla: reinstalar libs sistema (ver arriba)
```

### Scan lento en repo grande (>15 min)

Normal en repos grandes (>100k archivos). Para acelerar:

```bash
# Excluir directorios grandes con .aios-ignore
cat > .aios-ignore <<EOF
node_modules/
.git/
bin/
obj/
dist/
build/
EOF
```

---

## 7 · Actualización del framework

Cuando se libere versión nueva (tú recibes notificación del líder técnico):

```bash
cd aios-framework
git pull origin main
pip install -e . --upgrade
aios version   # verifica versión nueva
```

---

## 8 · Contacto / escalación

| Problema | Contacto |
|---|---|
| Acceso al repo (invite no llegó) | Christian Hernández · christianescamilla15@gmail.com |
| Bug en el framework (error Python) | Christian (NO editar código local · centralizado) |
| Duda sobre contenido de un doc Discovery | Consultor responsable de la app · workshop técnico |
| Falla permiso AMX (VPN / acceso red) | IT AMX · Luis Ertuche (vía Christian) |

---

**Versión de esta guía**: compatible con AIOS v3.7.5+ · actualizada 2026-04-27.

---

## 6 · Cambios v3.7.4 + v3.7.5 que afectan documentación generada

### Detector quality (v3.7.4 · 5 gaps cerrados)

Los detectores AIOS ahora producen menos false positives en documentación Discovery:

- **`AUTH-MISSING-NET-CONTROLLER`** · ya respeta class-level `[Authorize]` (12-line lookback) y método-inline `[Authorize(Roles=...)]` post-`[HttpPost]` (span-aware). Resultado en `02_hallazgos_mapped.md`: cero FPs sobre controllers .NET ya autorizados.
- **`STATIC-GENERIC-EXCEPTION-CATCH-CSHARP`** · `catch (Ex) when (...)` se degrada MED→LOW automáticamente (filter es intent específico, no sloppy catch-all). Doc reporta correctamente sev real.
- **`HARDCODED-INTERNAL-HOSTNAME` + alias `CWE-547`** · suppression con `rule: "CWE-547"` (alias) cubre detectores que emiten ese CWE con rule_id distinto. Reduce ruido en `05_vulns.md`.
- **`compliance-report` consume suppressions** · igual que `aios release` y `aios iterate`. Antes (≤v3.7.3) sólo `release` aplicaba waivers, lo que causaba divergencia entre marcos regulatorios y release gate.

### Framework path/timeout (v3.7.5 · 3 gaps cerrados)

Mejora robustez de `aios discovery-generate` y `aios compliance-report`:

- **`G-PATH-NORMALIZATION` (T8-N1)** · suppressions declaradas con repo-root path (`infra/cdk-pipeline/stacks/x.py`) ahora matchean findings emitidos con scope-reducido (`stacks/x.py` cuando `--root infra/cdk-pipeline`). Discovery generation con scope reducido respeta waivers correctamente.
- **`G-REGEX-TIMEOUT` (T8-N3)** · `_safe_finditer()` con `signal.SIGALRM` 2s default (override `AIOS_REGEX_TIMEOUT_SECONDS=N`). Cierra hangs sobre archivos YAML grandes (k8s manifests · 100+ LOC). Discovery generation completa < 90s incluso con `infra/k8s/`.
- **`compliance-report --output` resuelve relativo a CWD** · `aios compliance-report --root src --output reports/compliance.md` escribe en `<cwd>/reports/compliance.md` (no `src/reports/`). Comportamiento Unix-estándar.

### Override env vars (v3.7.5)

| Env var | Default | Uso |
|---|---|---|
| `AIOS_REGEX_TIMEOUT_SECONDS` | `2` | Aumentar para archivos extremadamente grandes (e.g., generated SQL files) |

### Migración suppressions (v3.7.4 → v3.7.5)

Si tu `aios-suppressions.json` tiene entries con `rule` (alias) o `rule_id="CWE-NNN"` (CWE-form):

- Antes (≤v3.7.3) · matcher requería `rule_id` exacto de detector. Suppressions con CWE-form fallaban.
- Ahora (≥v3.7.4) · alias `rule` aceptado · CWE-form fallback case-insensitive · separator-aware path normalization (v3.7.5).

**No se requiere migración** · entries existentes siguen funcionando · más entries pueden simplificarse usando alias `rule` o `rule_id="CWE-NNN"`.

### Tests cross-app (v3.7.4 + v3.7.5)

| Métrica | v3.7.3 | v3.7.4 | v3.7.5 |
|---|---:|---:|---:|
| Tests pass | 401 | 419 | **428** |
| Detectores AMX | 29 | 29 | 29 (quality only) |
| Subcommands consume suppressions | release | release · iterate · compliance-report | idem |

Para SICOFAV (post-v3.7.5):
- `aios iterate --root .` full-repo · 0 CRIT/HIGH/MED · 21 LOW · 4 suppressed
- `aios iterate --root infra/k8s/` ya no se cuelga · termina < 90s
- `aios discovery-generate --app sicofav --root <repo>` produce 9 docs sin FPs sobre code post-T6/T7/T8 fixes

---

**Versión de esta guía**: compatible con AIOS v3.7.5+ · actualizada 2026-04-27.
