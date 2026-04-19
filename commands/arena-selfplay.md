---
description: "Ejecuta Arena Mythos-vs-Nemesis self-play contra un TUT bajo demanda"
triggers:
  - "arena run"
  - "self-play"
  - "mythos vs nemesis"
  - "duelo arena"
  - "adversarial test"
  - "coliseum"
---

# Arena Self-Play

Ejecuta un duelo Mythos (defensa) vs Nemesis (ataque) contra un
Target-Under-Test. Emite verdict (MYTHOS_WINS · NEMESIS_WINS ·
STALEMATE · DRAW · USER_STOPPED) + timeline + findings.sarif.

## Pasos

1. Listar TUTs disponibles:
   ```bash
   aios arena --list
   ```
2. Escoger TUT del output (ej. `amx-mini-refund` o
   `amx-mini-sicofav-cs`).
3. Ejecutar static mode (sin HTTP · rapido):
   ```bash
   aios arena --target amx-mini-refund --max-rounds 10
   ```
4. (Opcional) Fase 4 live mode · requiere Docker + nuclei:
   ```bash
   # Levantar TUT container
   cd arena-targets/amx-mini-refund
   docker compose -p arena-tut up -d --build

   # Lanzar con nuclei real contra HTTP live
   aios arena --target amx-mini-refund \
     --target-url http://localhost:8888 \
     --max-rounds 10

   # Teardown
   docker compose -p arena-tut down
   ```

## Output

- Verdict impreso en la terminal
- Timeline · `arena-memory/runs/<run_id>/timeline.md`
- SARIF · `arena-memory/runs/<run_id>/findings.sarif` (subible a
  GitHub Security tab)
- Resumen apendado a `ai-memory/security_findings.md` (lo lee
  `aios status` automaticamente)

## Tiempo esperado

- Static mode · 10-30s por 10 rounds
- Live mode (Fase 4) · 1-2 min por round (nuclei + docker rebuild)
- Fase 4.5 (auto-redeploy) · ~4s overhead por round con patches

## Consejos

- Si aparece `[!!] redeploy FAILED · Conflict`, el container usa
  un project name distinto. Levantar con `docker compose -p arena-tut
  up -d --build`.
- Para debugging de bugs en detectores, `arena run <tut>
  --max-rounds 1` · inspeccionar `rounds/0001.json` bajo
  `arena-memory/runs/<run_id>/`.
