"""v3.7.0 · Discovery Package generator · 9 documentos Fase 1 via comandos.

Entrega automatizada de los 9 documentos que una fase 1 de modernización suele exigir
antes de diseñar el TO-BE (diseño + entrega a seguridad):

1. Resumen Técnico-Funcional (10 secciones)   · `discovery-resumen-tf`
2. C4 Context L1 (sistema + actores)          · `analyze` (existente)
3. C4 Container L2 (Mermaid)                  · `discovery-c4-l2`
4. C4 Component L3 (Mermaid)                  · `discovery-c4-l3`
5. ADR (Architecture Decision Record)         · `discovery-adr`
6. BIA (Business Impact Analysis)             · `discovery-bia`
7. Runbook operacional (Deploy + DR + IR)     · `discovery-runbook`
8. Compliance Report (LFPDPPP/PCI/SOX/OWASP)  · `compliance-report` (existente)
9. Evidence Bundle ZIP consolidado            · `phase1-report` (existente)

Orchestrator `discovery-package --app <n>` corre los 9 en secuencia + empaqueta.

Fuente metadata: `aios.core.portfolio.APPS` (portafolio ficticio de ejemplo).
"""
from __future__ import annotations
