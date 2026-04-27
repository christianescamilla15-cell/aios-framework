# Feature - Add notifications and permissions

## Tasks

### T1 — Config schema v2 + back-compat loader
- Description: Bump `aios.yml` schema to v2; add `notifications:` and `permissions:`
  blocks; loader treats missing blocks as no-op; `aios validate-config` rejects literal
  URLs/secrets and unknown roles.
- Owner Agent: config-agent
- Dependencies: none
- Validation: 401+ tests still green; new tests for v1->v2 migration and rejection cases.
- Risk: low

### T2 — Permissions model + enforcer + audit log
- Description: Implement `permissions.model`, `resolver`, `enforcer` (decorator),
  `audit` (hash-chained JSONL). Wire `@requires(Action.X)` on suppress/override/publish.
- Owner Agent: security-agent
- Dependencies: T1
- Validation: viewer-denied / reviewer-allowed unit tests; audit log replay verifies hash chain.
- Risk: medium  (fail-closed must not break existing CI — mitigate with `permissions:` absent => skip enforcement)

### T3 — Notification channels (stdout, file, email, webhook, github_pr)
- Description: Implement `Channel` ABC + 5 concrete channels. Each best-effort; failures
  log a WARN, never raise. Secrets resolved via existing `aios.secrets` helper.
- Owner Agent: notify-agent
- Dependencies: T1
- Validation: golden fixtures per channel (Slack JSON, email MIME, GH Markdown comment).
- Risk: medium  (webhook flakiness, SMTP TLS edge cases)

### T4 — Router + throttle + digest
- Description: Match findings against rules (app/severity/detector), apply SQLite-backed
  throttle window, build digest payload when N findings within window.
- Owner Agent: notify-agent
- Dependencies: T3
- Validation: time-travel tests with frozen clock; dedup window honored; digest count matches.
- Risk: low

### T5 — CLI: `aios notify`, `aios whoami`, `aios audit-tail`
- Description: Wire 3 new subcommands. `notify --dry-run` is the default in CI;
  `whoami` prints actor + role; `audit-tail` streams the hash-chained log with
  integrity check.
- Owner Agent: cli-agent
- Dependencies: T2, T4
- Validation: subcommand help screens, `--dry-run` produces zero side effects, exit codes match contract.
- Risk: low

### T6 — Detector G-NEW-NOTIFY-PLAINTEXT + G-NEW-PERMS-DRIFT
- Description: Two new YAML/Python detectors. Plaintext: regex over `notifications.*.url`
  / `host` looking for `https?://` literals not prefixed by `op://`/`env://`/`aws-sm://`.
  Drift: AST diff on `permissions.users[]` between current and baseline aios.yml; flag
  if changed without reviewer label.
- Owner Agent: detector-agent
- Dependencies: T1
- Validation: golden inputs (positive + negative) + 0 FPs on existing 6 baseline apps.
- Risk: medium  (drift detector touches PR metadata — must be optional in CLI mode)

### T7 — CI integration + CODEOWNERS
- Description: Add `.github/CODEOWNERS` entry locking `aios.yml` `permissions:` block
  to admins; add CI step `aios notify --dry-run` that fails the build on routing-config errors.
- Owner Agent: ci-agent
- Dependencies: T5, T6
- Validation: PR that edits `permissions.users[]` without admin review is blocked end-to-end.
- Risk: low

### T8 — Smoke run on 4 baselines + tag release
- Description: Run end-to-end on SICOFAV, NoShow, SRG, Robot. No regressions vs.
  prior baseline. Bump version, update `BACKLOG.md`, tag and push origin + amx.
- Owner Agent: release-agent
- Dependencies: T1–T7
- Validation: 4/4 baselines unchanged in finding count; new detectors show expected hits in fixtures only.
- Risk: low
