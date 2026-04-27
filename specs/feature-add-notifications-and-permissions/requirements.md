# Feature - Add notifications and permissions

## Objective
Add a notifications channel and a permissions/RBAC layer to AIOS so that:
- scan results (CRITICAL/HIGH findings, gate failures, baseline drift) reach the right humans
  through the right channel without manual triage,
- only authorized users can run privileged actions (override gate, suppress finding,
  publish baseline, edit detectors, edit waivers).

## User Impact
- Security lead / oncall: receives an actionable alert when a release gate fails,
  instead of discovering it on the next dashboard refresh.
- App owner (e.g. SICOFAV, NoShow): receives only findings tied to their app/repo.
- Auditor (Ibrahim, J.T., Reyes): receives weekly digest of waivers granted and
  CRITICAL findings still open, with author and timestamp.
- Detector author: cannot accidentally suppress a finding in production without a reviewer.

## Functional Requirements
- FR-1  Configurable channels: stdout, file, email (SMTP), webhook (Slack/Teams),
        GitHub PR comment. At least two MUST be selectable per project.
- FR-2  Notification routing: per-app, per-severity, per-detector. Routing rules live
        in `aios.yml` under `notifications:` and are validated by `aios validate-config`.
- FR-3  Triggers: (a) scan finishes with new CRITICAL or HIGH, (b) release gate fails,
        (c) waiver added/edited/expired, (d) baseline diff exceeds threshold.
- FR-4  Throttling: identical alert within N minutes is suppressed (default 60 min);
        digest mode rolls up multiple alerts into one message.
- FR-5  Permissions model: roles `viewer`, `developer`, `reviewer`, `admin`.
        Privileged actions require role >= `reviewer` (suppress, override-gate, publish-baseline,
        edit-detector, edit-waiver).
- FR-6  Permission source: file-backed (`aios.yml -> permissions:`) for CLI, with optional
        OIDC claim mapping for CI (env `AIOS_OIDC_CLAIMS_JSON`).
- FR-7  Audit log: every privileged action emits a structured JSON line to
        `.aios/audit.log` with actor, action, target, timestamp, justification.
- FR-8  Dry-run mode: `aios notify --dry-run` renders the message that *would* be sent
        without delivering it; required in CI before merging routing changes.

## Non-Functional Requirements
- NFR-1 No secret in plaintext: SMTP/webhook URLs come from secret store
        (env, AWS Secrets Manager, or `op://`); detector G-NEW-NOTIFY-PLAINTEXT enforces this.
- NFR-2 Delivery is best-effort, never blocks a scan: failures logged, not raised.
- NFR-3 Permissions check is fail-closed: missing role => denied, never default-allow.
- NFR-4 Audit log is append-only and tamper-evident (hash-chained per line).
- NFR-5 Adds < 200 ms p95 to a scan that produces 0 findings.

## Acceptance Criteria
- [ ] `aios scan` with a CRITICAL finding sends one Slack message and one email,
      content matches golden fixture.
- [ ] `aios suppress <finding-id>` run by a `viewer` exits non-zero with
      `permission denied: requires role >= reviewer`.
- [ ] `aios suppress <finding-id>` run by a `reviewer` succeeds and writes
      one line to `.aios/audit.log` with `action=suppress`.
- [ ] Same finding triggered twice within 60 min produces exactly one message;
      third trigger after window produces a second message.
- [ ] `aios validate-config` rejects `aios.yml` with a webhook URL containing
      `https://hooks.slack.com/...` literal (must be a secret reference).
- [ ] G-NEW-NOTIFY-PLAINTEXT detector flags a plaintext webhook URL with severity HIGH.
- [ ] Smoke suite passes on SICOFAV, NoShow, SRG, Robot baselines (no regressions).

## Out of Scope
- SMS / phone-call paging (use existing PagerDuty integration instead).
- UI for editing permissions (CLI + YAML only in v1).
- Mobile push notifications.
- Per-finding ACL (only per-app / per-severity / per-detector in v1).
- Replacing GitHub branch protection (AIOS permissions are *additional*, not a substitute).
