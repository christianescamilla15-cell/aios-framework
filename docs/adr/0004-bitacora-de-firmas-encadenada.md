# ADR 0004 · Bitácora de firmas append-only encadenada por SHA-256 y máquina de estados explícita

- Estado: aceptada · Fecha: 2026-11-24 (registra la decisión de la 3.8)

## Contexto
Las solicitudes de accesos y recursos pasan por varias firmas y se atoran. Hace falta saber en qué estado
está cada una, desde cuándo, y poder demostrar que nadie reescribió el historial, sin depender de un
servidor ni de una base de datos.

## Decisión
- `.aios/governance/audit-trail.jsonl` es append-only: cada entrada lleva el SHA-256 de la anterior y el
  suyo propio; `verify_chain()` detecta cualquier edición.
- Los estados forman una máquina explícita de 11 estados (`VALID_TRANSITIONS`); la primera entrada sólo
  puede ser `draft` o `requested`; `rejected`, `cancelled` y `revoked` son terminales. `approvals.yaml`
  documenta la misma máquina y una prueba exige que coincidan.
- El atraso se mide desde la última entrada de cada solicitud no terminal con umbrales del YAML (3/5/10
  días) y la severidad decide a quién se escala.

## Alternativas
- *Base de datos o servicio*: más consultas, pero exige infraestructura para una herramienta de terminal.
- *Archivo editable (CSV/YAML)*: sin evidencia de manipulación.

## Consecuencias
La bitácora viaja con el repositorio del proyecto y se audita sin herramientas externas. La concurrencia no
está resuelta (dos escritores a la vez rompen la cadena): es para uso de un equipo pequeño desde la CLI.
Pruebas: `tests/test_governance_audit_trail.py` (121 transiciones contra un oráculo, manipulación, fronteras
de atraso).
