# Piloto NoShow · prompt para Kiro

**Target:** `apps/10-noshow/` o `apps_code/atos-noshow/` (el proyecto real · no el frankenstein sintético)
**Modo:** LEGACY_MODERNIZATION
**Precondición:** Power `amx-aios-unified` v1.7.4+ activo · `aios-mcp` en PATH · aios-framework 1.7.4 instalado
**Start:** `aios checkpoint --phase-completed '' --phase-in-progress 'FASE 0 · boot'` (establece anchor inicial)

---

## Prompt a copiar al chat de Kiro (auto mode)

```
LEGACY_MODERNIZATION · ATOS-NOSHOW · modernización .NET 4.7.2 → .NET 8 LTS · end-to-end hasta pre-deploy · AMX post-retro 20-abr compliant

═══════════════════════════════════════════════════════════════
CONTEXTO DEL PROYECTO (real · no sintético)
═══════════════════════════════════════════════════════════════
ATOS NoShow es una aplicación legacy C# .NET 4.7.2 que procesa reservas no-show para Aeroméxico. Está en scope del audit hallazgos revenue-accounting con FRKs documentados:
- FRK-037 · vuelo 829 hardcoded en NoShowService.cs · CRITICAL
- FRK-038 · ATOS5246 legacy service account · HIGH
- (+ otros FRKs específicos del proyecto real)

El spec-driven ya fue probado en Test 3 (ver specs/atos-noshow-modernization-validation/ en aios-framework) que produjo 1,507 líneas · 109 tasks · 10 BLOCKERS gates AMX. Usar ese material como input base · no regenerar desde cero.

═══════════════════════════════════════════════════════════════
RESTRICCIONES AMX POST-RETRO 20-ABR (NO NEGOCIABLES)
═══════════════════════════════════════════════════════════════
- Secrets: AWS Secrets Manager (NO env vars · NO inline)
- Crypto: KMS + rotación 90d
- Edge: Akamai (NO CloudFront)
- Compute: EKS o Lambda (NO ECS)
- Mensajería: EventBridge + SQS (NO SES/SNS)
- Observabilidad: correlation-id obligatorio
- Naming IAM: amx-r-noshow-<env>
- Networking: Route53 Private Zones (NO IPs hardcoded)

═══════════════════════════════════════════════════════════════
FLUJO (8 fases · auto mode autónomo)
═══════════════════════════════════════════════════════════════

FASE 0 · Boot
  - aios checkpoint --phase-in-progress "FASE 0 · boot"
  - Lee ai-memory/ existente O bootstrap con 6 archivos canónicos
  - Carga aios-config.json con forbidden_literals AMX
  - Confirma aios-mcp conectado

FASE 1 · Discovery
  - aios checkpoint --phase-completed "FASE 0" --phase-in-progress "FASE 1 · discovery"
  - security_scan(apps/10-noshow/) baseline
  - aggregate_report pre-refactor · snapshot
  - Lee specs/atos-noshow-modernization-validation/ · usa como master spec

FASE 2 · Refactor
  - aios checkpoint --phase-completed "FASE 1" --phase-in-progress "FASE 2 · refactor"
  - Resuelve los FRKs del proyecto (FRK-037, FRK-038, otros específicos)
  - Build gate: dotnet build · 0 errores · 0 warnings
  - Tests regresión por FRK
  - Commit atómico: "fix · FRK-XXX · <desc>"
  - aios checkpoint --last-commit <hash> después de cada FRK resuelto

FASE 3 · Shared infra + CI/CD
  - AmxNoShow.sln · Dockerfile multi-stage distroless · .github/workflows/ csharp-build + security-scan + release-gate + container-build + sbom
  - aios checkpoint --phase-completed "FASE 2" --phase-in-progress "FASE 3"

FASE 4 · Observability + Security hardening
  - Correlation-ID middleware · Serilog JSON · Prometheus metrics · Health checks · OpenTelemetry
  - ISecretsProvider + AWS Secrets Manager client · KMS helper · OWASP checklist · SBOM SPDX

FASE 5 · Deployment artifacts
  - Dockerfile · docker-compose · k8s/base/ + overlays/{dev,staging,prod} kustomize
  - helm/atos-noshow/ · terraform/atos-noshow/ (ECR + IAM amx-r-noshow-* + Secrets + KMS + CloudWatch)

FASE 6 · Performance & Resilience
  - perf/k6/atos-noshow.js (smoke + load + stress)
  - chaos/chaos-mesh/ · Circuit breakers (Polly) · retries · timeouts · bulkheads

FASE 7 · Docs
  - docs/ARCHITECTURE.md (C4) · docs/adrs/ (8 ADRs) · docs/runbooks/ (deploy-staging · rollback · incident)
  - docs/SECURITY.md + OWASP + PCI-DSS · docs/api/OpenAPI.yaml · README actualizado

FASE 8 · Final validation + Release Gate
  - security_scan POST · delta vs baseline (target: 0 CRITICAL)
  - release_gate_check · 7 AMX checks · objetivo READY
  - aggregate_report POST · snapshot final
  - aios checkpoint --phase-completed "FASE 8" --phase-in-progress "" --next-action "handoff pre-deploy"

REPORTE FINAL: genera docs/FINAL_REPORT_NOSHOW_PILOT.md con:
  1. Executive summary · delta findings · build gates · tests · verdict pre-deploy
  2. FRKs resueltos (tabla · FRK-ID / fix / commit)
  3. Commits creados (git log --oneline)
  4. Pre-deploy checklist 20+ items (✓/✗)
  5. Timing: wall-clock + elapsed activo por fase
  6. Gates AMX externos pendientes (WIZ · Veracode · Prisma · Tenable · Miguel Rachid approval)
  7. Comparativa vs frankenstein-70k sintético (validar que el framework escala del sintético al real)

═══════════════════════════════════════════════════════════════
REGLAS OPERATIVAS
═══════════════════════════════════════════════════════════════
- Auto mode · sin preguntar entre fases · reporta cada 2 fases
- Checkpoint OBLIGATORIO después de cada fase (aios checkpoint ...)
- Si hit context limit: user escribe "continua" · agente hace "aios resume" y retoma exacto
- Build gates ANTES de siguiente FRK · no skip · no --no-verify
- Commits atómicos por FRK · mensaje español · formato "fix · FRK-XXX · <desc>"
- No-destructive · no git push --force · no reset --hard
- Test failures out-of-scope: documentar en OUT_OF_SCOPE_FINDINGS.md

ARRANCA FASE 0 AHORA.
```

---

## Para lanzar

1. **Verifica v1.7.4 instalado**:
   ```powershell
   pip show aios-kiro | Select-String Version  # debe ser 1.7.4
   ```
2. **Abre Kiro en `apps/10-noshow/`** (o el path real del proyecto ATOS-NOSHOW)
3. **Activa el Power** `amx-aios-unified` (debe estar instalado · ver POWERS sidebar)
4. **Inicia sesión kcb** para trazabilidad:
   ```powershell
   wsl -d Ubuntu-24.04 --cd /mnt/c/Users/eTriber/Desktop/amx-hallazgos-audit `
     ./.venv-mythos/bin/kcb start `
     --id "ses-pilot-noshow-$(Get-Date -Format yyyyMMddTHHmmssZ)" `
     --actor kiro `
     --label "Piloto NoShow · proyecto real · end-to-end hasta pre-deploy"
   ```
5. **Copia el prompt de arriba** al chat de Kiro · dispara
6. **Monitorea** cada 30-60 min:
   ```powershell
   git log --oneline -10
   aios resume  # muestra el checkpoint actual
   ```

---

## Ventaja vs frankenstein-70k

| Aspecto | frankenstein-70k (sintético) | pilot NoShow (real) |
|---|---|---|
| Código | generado programáticamente | producción legacy AMX |
| FRKs | 79 sembrados con gold standard | reales del audit |
| Validación | precision/recall vs seed | validación funcional del negocio |
| Evidencia para Ibrahim | "escala técnica" | **"caso real AMX"** ← mucho más fuerte |
| Stakeholders | solo técnico | Diego Zarate · Miguel Rachid · tu equipo |

Este piloto es la evidencia DEFINITIVA para la contribución a OYN-AMX · cierra el loop framework técnico → valor operativo real.
