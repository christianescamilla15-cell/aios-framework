# Reglas → pruebas

Cada regla del dominio de AIOS y las pruebas que la fijan (`archivo::función`). Ésta es la compuerta real
del CI; la cobertura sólo se reporta. Las reglas de organización usan los datos ficticios de Acme Corp
(ver [ADR 0003](adr/0003-reglas-de-organizacion-como-datos-de-ejemplo.md)).

## Security gate

| # | Regla | Pruebas |
|---|---|---|
| S1 | Cada uno de los 123 detectores dispara con un caso positivo y no con uno negativo | `tests/test_detectores_golden.py::test_positivo_dispara_y_negativo_no` (55 reglas del oráculo) · resto en `tests/test_security_gate.py` |
| S2 | Ningún detector existe sin prueba (compuerta) | `tests/test_detectores_golden.py::test_todo_detector_tiene_al_menos_una_prueba` |
| S3 | Paridad del corpus contra el oráculo escrito a mano, con cifras control y control negativo | `tests/test_detectores_golden.py::test_corpus_completo_cuadra_con_el_oraculo` · `tests/test_detectores_golden.py::test_control_negativo_la_comparacion_detecta_un_positivo_faltante` · `tests/test_detectores_golden.py::test_oraculo_sin_duplicados_ni_reglas_inexistentes` |
| S4 | Un hallazgo dentro de un comentario se descarta | `tests/test_security_gate.py::test_flask_debug_does_not_fire_on_comment` |
| S5 | Los anclajes multilínea no cruzan a la línea anterior (el hallazgo no se pierde ni cambia de línea) | `tests/test_security_gate.py::test_multiline_anchor_does_not_cross_previous_line` |
| S6 | Cada regex corre con tiempo máximo configurable | `tests/test_security_gate.py::test_safe_finditer_normal_match` · `tests/test_security_gate.py::test_safe_finditer_unix_signal_handler_restored` · `tests/test_security_gate.py::test_safe_finditer_timeout_constant_overridable` |
| S7 | Una supresión aplica por regla + archivo + línea (0 = cualquier línea), con respaldo por CWE | `tests/test_suppressions.py::test_suppression_matches_exact` · `tests/test_suppressions.py::test_suppression_line_zero_is_wildcard` · `tests/test_suppressions.py::test_matches_falls_back_to_cwe_when_rule_id_is_cwe_form` · `tests/test_suppressions.py::test_matches_cwe_fallback_does_not_match_when_cwe_differs` |
| S8 | Una supresión vencida deja de aplicar | `tests/test_suppressions.py::test_is_expired_past_date` · `tests/test_suppressions.py::test_apply_suppressions_ignores_expired` |
| S9 | Una supresión con ruta desde la raíz aplica a un escaneo de subdirectorio, sin falsos cruces | `tests/test_suppressions.py::test_paths_match_helper_scope_reduced` · `tests/test_suppressions.py::test_paths_match_helper_separator_aware` · `tests/test_suppressions.py::test_e2e_suppression_matches_with_scope_reduced_finding` |
| S10 | El gate y `aios iterate` respetan las mismas supresiones | `tests/test_suppressions.py::test_security_gate_respects_suppressions` · `tests/test_iterative_scanner_suppressions.py` |
| S11 | Los literales prohibidos se cuentan pero nunca se devuelven por MCP | `tests/test_mcp_server.py::test_forbidden_literals_suggest_does_not_leak` |

## Clasificación antes del auto-fix

| # | Regla | Pruebas |
|---|---|---|
| C1 | Bug con `auto_fix_allowed` → se corrige solo | `tests/test_reglas_analisis.py::test_bug_with_auto_fix_allowed_is_auto_fixed` |
| C2 | Regla de negocio → se pausa para revisión con su mensaje y la evidencia requerida | `tests/test_reglas_analisis.py::test_business_rule_pauses_for_review_with_its_message` |
| C3 | Varias coincidencias: gana bug > regla de negocio > migración > dudoso; las demás se conservan | `tests/test_reglas_analisis.py::test_multi_match_ranks_bug_over_migration_and_keeps_the_rest` |
| C4 | Sin coincidencia → valor por omisión seguro de la ontología; sin ontología → compatibilidad (auto-fix) | `tests/test_reglas_analisis.py::test_no_match_falls_back_to_safe_default` · `tests/test_reglas_analisis.py::test_missing_ontology_keeps_backwards_compatible_auto_fix` · `tests/test_reglas_analisis.py::test_skip_pattern_by_path` |
| C5 | La última decisión humana gana; rechazado bloquea, aprobado sale, desconocido queda pendiente | `tests/test_reglas_analisis.py::test_decisions_split_findings_and_the_latest_one_wins` · `tests/test_reglas_analisis.py::test_unknown_action_is_treated_as_pending` · `tests/test_reglas_analisis.py::test_finding_id_is_deterministic_and_location_sensitive` |

## Analizadores de apoyo

| # | Regla | Pruebas |
|---|---|---|
| A1 | Misma credencial en archivo de QA/test y de producción → CRITICAL; sin ambiente en el nombre → HIGH; el valor nunca se imprime | `tests/test_reglas_analisis.py::test_same_credential_in_qa_and_prod_files_is_critical` · `tests/test_reglas_analisis.py::test_same_credential_without_environment_in_name_is_high` |
| A2 | Credenciales distintas o referencias a un almacén de secretos no son hallazgo | `tests/test_reglas_analisis.py::test_different_credentials_are_not_reported` · `tests/test_reglas_analisis.py::test_references_to_a_secret_store_are_not_credentials` |
| A3 | Destinatario externo: producción HIGH, pruebas INFO, sin pista MEDIUM; dominio corporativo y subdominios excluidos | `tests/test_reglas_analisis.py::test_external_recipient_severity_depends_on_environment` · `tests/test_reglas_analisis.py::test_corporate_and_subdomains_are_not_exfil` |
| A4 | PAN sólo con Luhn válido y redactado; localizador sólo con palabra clave cerca | `tests/test_reglas_analisis.py::test_runtime_data_detects` · `tests/test_reglas_analisis.py::test_runtime_data_ignores` · `tests/test_reglas_analisis.py::test_runtime_data_redacts_the_card_number` |
| A5 | Compuerta de cobertura: línea/rama bajo umbral falla; paquetes SOX exigen 100 % | `tests/test_coverage_gate.py::test_apply_gate_fails_on_low_line` · `tests/test_coverage_gate.py::test_apply_gate_fails_on_low_branch` · `tests/test_coverage_gate.py::test_apply_gate_sox_critical_fails_below_threshold` · `tests/test_coverage_gate.py::test_apply_gate_sox_critical_passes_when_100` |

## Gobierno

| # | Regla | Pruebas |
|---|---|---|
| G1 | T3 prohíbe datos personales: una app con PII declarada T3 se marca HIGH y se sugiere T2 | `tests/test_governance_tier_classifier.py::test_partners_hypothetical_t3_triggers_pii_mismatch` |
| G2 | T0/T1 no comparten cuenta | `tests/test_governance_tier_classifier.py::test_t0_t1_no_shared_account_detected_when_in_shared` |
| G3 | T0 exige activo-activo en dos regiones | `tests/test_governance_tier_classifier.py::test_payments_t0_detects_multiregion_missing` |
| G4 | El RTO del BIA de una T0 no supera el de `tiers.yaml` | `tests/test_governance_tier_classifier.py::test_t0_rto_bia_detector_triggers_for_payments` · `tests/test_governance_tier_classifier.py::test_rto_extracted_from_rationale_text` |
| G5 | Las apps `out_of_scope_*` salen del alcance pero siguen en el catálogo | `tests/test_governance_loader.py::test_supported_apps_excludes_out_of_scope_apps` · `tests/test_governance_loader.py::test_all_apps_includes_out_of_scope_for_history` |
| G6 | Rol IAM `acme-role-{app}-{admin\|dev\|readonly}`; prefijo reservado exento | `tests/test_governance_naming_checker.py::test_iam_role_naming_fails_for_non_compliant_suffix` · `tests/test_governance_naming_checker.py::test_iam_role_naming_flags_uppercase_variant` · `tests/test_governance_naming_checker.py::test_iam_role_naming_skips_reserved_service_prefix` |
| G7 | Alias KMS y secretos siguen la convención; alias de terceros no se juzgan | `tests/test_governance_naming_checker.py::test_cmk_naming_fails_for_unknown_scope` · `tests/test_governance_naming_checker.py::test_cmk_naming_ignores_third_party_aliases` · `tests/test_governance_naming_checker.py::test_secret_naming_fails_for_missing_app` · `tests/test_governance_naming_checker.py::test_secret_naming_fails_for_underscore` |
| G8 | Llave administrada por AWS (`alias/aws/*`) → CRITICAL | `tests/test_governance_naming_checker.py::test_kms_aws_managed_alias_flags_critical` · `tests/test_governance_naming_checker.py::test_kms_customer_managed_alias_passes` |
| G9 | Los ejemplos documentados en `naming.yaml` cumplen / no cumplen su propio patrón | `tests/test_governance_naming_checker.py::test_examples_in_naming_yaml_are_self_consistent` |
| G10 | Bitácora: 121 transiciones contra un oráculo; sólo draft/requested inician; terminales sin salida; el YAML documenta la misma máquina | `tests/test_governance_audit_trail.py::test_every_transition_matches_the_oracle` · `tests/test_governance_audit_trail.py::test_first_entry_only_draft_or_requested` · `tests/test_governance_audit_trail.py::test_terminal_states_have_no_exit` · `tests/test_governance_audit_trail.py::test_append_entry_rejects_invalid_transition` · `tests/test_governance_audit_trail.py::test_approvals_yaml_documents_the_same_state_machine` |
| G11 | La cadena SHA-256 detecta cualquier edición | `tests/test_governance_audit_trail.py::test_append_entry_chains_prev_hash` · `tests/test_governance_audit_trail.py::test_verify_chain_detects_tampering` |
| G12 | Atraso: 3/5/10 días → aviso/escalamiento/emergencia (el borde ya pertenece al nivel); terminales no cuentan | `tests/test_governance_audit_trail.py::test_slippage_severity_boundaries` · `tests/test_governance_audit_trail.py::test_detect_slippage_skips_terminal_states` |
| G13 | Escalamiento por severidad a los destinatarios de `approvals.yaml`; `--to` sólo acepta llaves conocidas | `tests/test_governance_escalation_engine.py::test_warn_routes_to_pmo` · `tests/test_governance_escalation_engine.py::test_escalate_routes_to_sponsor` · `tests/test_governance_escalation_engine.py::test_emergency_routes_to_steering_committee` · `tests/test_governance_escalation_engine.py::test_manual_to_overrides_severity_routing` · `tests/test_governance_escalation_engine.py::test_manual_to_invalid_raises` · `tests/test_governance_escalation_engine.py::test_no_slippage_returns_none` |
| G14 | Cada tipo de solicitud se genera para cada app en alcance; tipo desconocido se rechaza; la solicitud abre su entrada en la bitácora | `tests/test_governance_request_engine.py::test_every_request_type_renders_for_every_app` · `tests/test_governance_request_engine.py::test_generate_invalid_resource_type_raises` · `tests/test_governance_request_engine.py::test_generate_creates_audit_entry_with_chain` |
| G15 | Cuenta T2 compartida lista sólo sus apps; T0 dedicada | `tests/test_governance_request_engine.py::test_shared_account_lists_only_its_consolidated_apps` · `tests/test_governance_request_engine.py::test_for_aws_account_t0_marks_dedicated` |
| G16 | Portafolio de modernización y `tiers.yaml` describen las mismas apps con el mismo TIER | `tests/test_discovery_generate.py::test_portfolio_tiers_match_governance_assignments` |
| G17 | El catálogo sólo referencia repos y productos que existen | `tests/test_org_catalog.py::test_every_analog_and_product_in_mappings_exists` |

## Endurecimiento (entrada no confiable)

| # | Regla | Pruebas |
|---|---|---|
| E1 | La extensión invoca la CLI sin shell | `tests/test_kiro_integration.py::test_vscode_extension_never_runs_cli_through_a_shell` |
| E2 | XML con entidades se rechaza (cobertura) o cae al parser por regex (configuración) | `tests/test_endurecimiento.py::test_coverage_xml_with_entities_is_rejected` · `tests/test_endurecimiento.py::test_drift_config_with_entities_falls_back_to_regex` |
| E3 | Webhook y host de Ollama sólo http(s) | `tests/test_endurecimiento.py::test_slack_webhook_must_be_http` · `tests/test_endurecimiento.py::test_ollama_host_must_be_http` |
| E4 | Sólo se importan stacks de la lista blanca | `tests/test_endurecimiento.py::test_stack_checks_reject_unknown_stack_without_importing` · `tests/test_endurecimiento.py::test_stack_info_for_unknown_stack_is_inert` |
| E5 | El paquete instalado (wheel) trae sus reglas y plantillas y arranca fuera del árbol | job `paquete` de `.github/workflows/ci.yml` (`herramientas/humo.sh`) |
