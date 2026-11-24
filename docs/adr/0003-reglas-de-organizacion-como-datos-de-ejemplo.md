# ADR 0003 · Las reglas de organización son datos, y las del repositorio son de una organización ficticia

- Estado: aceptada · Fecha: 2026-11-24

## Contexto
El paquete de gobierno (TIER, nombres, cadena de firmas, interesados), el portafolio de modernización, el
catálogo de repos y una parte de los detectores (`ORG-*`) codifican reglas de UNA organización: qué servicios
aprueba, cómo nombra roles y llaves, quién firma. Un repositorio público no puede contener las reglas, las
personas ni los sistemas de una organización real, ni siquiera renombradas: la estructura, las cifras y las
fechas también identifican.

## Decisión
- Las reglas viven en datos (`aios/governance/rules/*.yaml`, `aios/core/portfolio.py`,
  `aios/core/org_catalog.py`); el código no conoce personas ni organizaciones. El enrutamiento de escalamiento,
  que antes estaba en el código, sale de `approvals.yaml`.
- Los datos que trae el repositorio describen a **Acme Corp, una organización ficticia**: 8 aplicaciones
  inventadas, roles con buzones del dominio reservado `.example` (RFC 2606) y cifras de ejemplo. Las reglas
  `ORG-*` (servicios en retiro, prefijo de roles, etiquetas, wrapper de CDK, zona horaria en buildspec) son
  una política de ejemplo; las `AWS-*` son buenas prácticas generales.
- La versión pública arranca con historia nueva (4.0.0). La compuerta `confidencialidad` del flujo
  `seguridad` revisa cada archivo contra una lista de términos que vive en el secreto `CONFIDENCIAL_TERMINOS`.

## Alternativas
- *Anonimizar renombrando*: descartado; un renombre deja la estructura y el dominio reconocibles.
- *Quitar el paquete de gobierno*: descartado; es una capacidad del framework y sus pruebas fijan el motor.

## Consecuencias
Usarlo en una organización real es reemplazar los YAML (mismas llaves) y, si aplica, `portfolio.py` y
`org_catalog.py`. Las pruebas fijan los valores ficticios (p. ej. 7 apps en alcance, T0 con RTO de 15 min):
cambiar los datos obliga a ajustar las pruebas en el mismo cambio. `test_portfolio_tiers_match_governance_assignments`
mantiene coherentes portafolio y TIER.
