---
description: "Ejecuta aios release con security gate embedded (9 CWEs + forbidden literals)"
triggers:
  - "security gate"
  - "release gate"
  - "scan before release"
  - "check security"
  - "seguridad pre-release"
  - "security scan"
---

# Security Scan · Release Gate

Ejecuta `aios release` que incluye el check de security static scan
(scanner embedded regex · 34 detectores multi-language) junto con los
otros 6 checks de release readiness.

## Pasos

1. Asegura que el cwd del proyecto tiene `aios-config.json` con
   seccion `security_gate` configurada. Defaults razonables:
   ```json
   {
     "security_gate": {
       "enabled": true,
       "strict": false,
       "max_critical": 0,
       "max_high": 5,
       "forbidden_literals": []
     }
   }
   ```
2. Ejecuta:
   ```bash
   aios release
   ```
3. Lee el output: `[OK]` `[!!]` `[XX]` por check + breakdown de
   findings por severity.
4. Si hay CRITICAL > `max_critical` · release BLOQUEADO.

## Si bloquea por security

- Revisa `Top findings` del output · cada uno tiene `cwe · rule_id ·
  file:line`.
- Aplica el patch template equivalente o fixea manualmente.
- Re-ejecuta `aios release`.

## Fuera del scope de este check

- No corre Arena self-play (usa `arena-selfplay` skill para eso).
- No corre Mythos con catalogos ACME completos (usa `mythos-scan-acme`
  si tienes mythos CLI instalado).
- No corre herramientas externas (semgrep · bandit · nuclei).

## Para habilitar delegacion a Mythos CLI

```json
{
  "security_gate": {
    "use_mythos_cli": true,
    "mythos_target_id": "01-fleet_ops_app"
  }
}
```

Con `mythos` en PATH, AIOS delegara el scan profundo para findings
con catalogos ACME.
