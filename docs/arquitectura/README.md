# Arquitectura · aios-framework (Dowser)

Modelo C4: contexto → contenedores → componentes. Los diagramas son texto (Mermaid) y se versionan con el
código; los nombres de componentes son módulos reales del paquete `aios`.

## 1. Contexto

```mermaid
C4Context
  title Contexto · AIOS
  Person(dev, "Ingeniero", "Moderniza o desarrolla una aplicación con flujo spec-driven")
  Person(aprobador, "Aprobador", "Firma solicitudes de accesos y recursos")
  System(aios, "AIOS", "Specs + security gate + gobierno como código + discovery de modernización")
  System_Ext(repo, "Repositorio analizado", "Código, configuración, IaC y specs del proyecto")
  System_Ext(kiro, "Kiro / agente IA", "Consume steering y herramientas MCP")
  System_Ext(llm, "Proveedor LLM", "Anthropic · OpenAI · Ollama (opcional)")
  System_Ext(oss, "Escáneres OSS", "Semgrep · Trivy · Checkov · gitleaks · bandit · npm audit (opcionales)")
  System_Ext(chat, "Webhook de chat", "Slack u otro compatible (opcional)")
  Rel(dev, aios, "Usa", "CLI · VS Code")
  Rel(kiro, aios, "Invoca", "MCP (stdio)")
  Rel(aios, repo, "Lee y escribe .aios/ y specs/")
  Rel(aios, llm, "Clasifica hallazgos", "HTTPS")
  Rel(aios, oss, "Ejecuta y normaliza", "subprocess")
  Rel(aios, chat, "Notifica", "HTTPS")
  Rel(aprobador, aios, "Registra firmas", "aios governance audit")
```

## 2. Contenedores

```mermaid
C4Container
  title Contenedores · AIOS
  Person(dev, "Ingeniero")
  System_Ext(kiro, "Kiro / agente IA")
  System_Boundary(b, "AIOS") {
    Container(cli, "CLI aios", "Python 3.11+ · argparse", "aios/cli/main.py + governance.py · ~60 subcomandos")
    Container(mcp, "Servidor MCP aios-mcp", "Python · FastMCP (mcp<2)", "aios/mcp_server.py · 8 herramientas")
    Container(ext, "Extensión VS Code", "TypeScript", "vscode-extension/ · comandos, barra de estado, snippets")
    Container(kirocfg, "Steering y power de Kiro", "Markdown + mcp.json", ".kiro/steering · powers/aios-unified")
    ContainerDb(reglas, "Reglas como datos", "YAML + Jinja2", "aios/governance/rules · templates · stacks/*/rules.md")
    ContainerDb(estado, "Estado del proyecto", "JSON/JSONL en .aios/", "caché, bitácora de firmas, revisiones, checkpoints")
  }
  Rel(dev, cli, "Ejecuta", "terminal")
  Rel(dev, ext, "Usa", "VS Code")
  Rel(ext, cli, "execFile (sin shell)")
  Rel(kiro, kirocfg, "Carga")
  Rel(kiro, mcp, "Llama herramientas", "stdio")
  Rel(mcp, cli, "Reusa el núcleo", "import aios.core")
  Rel(cli, reglas, "Lee")
  Rel(cli, estado, "Lee y escribe")
```

## 3. Componentes de la CLI

```mermaid
C4Component
  title Componentes · CLI aios
  Container_Boundary(core, "aios.core / aios.governance") {
    Component(spec, "Motor de specs", "router · spec_engine · prompt_engine · refine · memory_engine · steering · kiro_bridge", "Modo (BUGFIX/FEATURE/MIGRATION/LEGACY), specs EARS, sesión y handoff")
    Component(gate, "Security gate", "security_gate · file_scanner · suppressions · compliance", "123 detectores por regex con CWE, timeout por regex, supresiones con vencimiento, mapeo LFPDPPP/PCI/SOX/OWASP")
    Component(clasif, "Clasificación antes del auto-fix", "ontology · llm_classifier · review · characterization", "Ontología de dominio, LLM opcional, revisión humana con bitácora, huella de API")
    Component(extra, "Analizadores de apoyo", "drift_detector · exfil_detector · runtime_data_scanner · iterative_scanner · ensemble_scanner · dynamic_hooks", "Drift entre copias, exfiltración, PII en datos, saturación multi-estrategia")
    Component(wraps, "Envolturas de escáneres", "semgrep_scan · trivy_scan · checkov_scan · sbom · npm_audit · coverage_gate", "Normalizan herramientas externas a hallazgos AIOS")
    Component(release, "Release gate", "release_gate · test_runner · report_aggregator · trending · notifications", "Compuerta de salida y reporte consolidado")
    Component(gov, "Paquete de gobierno", "loader · tier_classifier · checkers · request_engine · escalation_engine · audit_trail", "TIER, nombres, solicitudes, escalamiento y bitácora SHA-256")
    Component(disc, "Discovery de modernización", "portfolio · discovery · phase1_report · org_catalog · buildspec_validate", "9 entregables de fase 1, análogos y plantillas de CI")
    Component(stacks, "Módulos por stack", "module_loader · repo_analyzer · stacks/*", "Detección de stack y checks por tecnología")
  }
  Rel(release, gate, "Corre")
  Rel(release, clasif, "Aplica decisiones humanas y huella de comportamiento")
  Rel(gate, clasif, "Clasifica cada hallazgo")
  Rel(extra, gate, "Comparte supresiones y formato de hallazgo")
  Rel(disc, gate, "Escanea el repo para 01_code_scan")
  Rel(disc, gov, "Mismas apps y TIER que tiers.yaml")
  Rel(spec, stacks, "Detecta stack")
```

## 4. Componentes del paquete de gobierno

```mermaid
C4Component
  title Componentes · aios.governance
  ContainerDb(yaml, "rules/*.yaml", "YAML", "tiers · naming · approvals · stakeholders (organización ficticia)")
  ContainerDb(tpl, "templates/*.j2", "Jinja2", "Solicitudes y correo de escalamiento en Markdown")
  ContainerDb(trail, ".aios/governance/audit-trail.jsonl", "JSONL append-only", "Entradas encadenadas por SHA-256")
  Container_Boundary(g, "aios.governance") {
    Component(loader, "loader", "Python", "Carga y cachea los 4 YAML")
    Component(tier, "tier_classifier", "Python", "9 criterios + reglas T0–T3")
    Component(checkers, "checkers", "Python", "naming · tier · approvals (atraso)")
    Component(req, "request_engine", "Python", "Contexto por tipo de solicitud → Markdown/PDF + entrada inicial")
    Component(esc, "escalation_engine", "Python", "Detecta atraso y enruta por severidad")
    Component(audit, "audit_trail", "Python", "Máquina de 11 estados + cadena SHA-256")
  }
  Rel(loader, yaml, "Lee")
  Rel(tier, loader, "Usa")
  Rel(checkers, loader, "Usa")
  Rel(req, tpl, "Renderiza")
  Rel(esc, tpl, "Renderiza")
  Rel(req, audit, "Registra solicitud")
  Rel(esc, audit, "Lee atrasos y registra envío")
  Rel(audit, trail, "Agrega y verifica")
```

## Decisiones

Ver [docs/adr/](../adr/): registro de decisiones (0001), detectores por regex embebidos (0002), reglas de
organización como datos de ejemplo (0003) y bitácora de firmas encadenada (0004).
