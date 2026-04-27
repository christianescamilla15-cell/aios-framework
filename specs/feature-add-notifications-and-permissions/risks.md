# Feature - Add notifications and permissions

## Known Risks

### R-1  Self-promotion via PR
Anyone with write access to a repo containing `aios.yml` could open a PR that
promotes their email to `admin`. Without enforcement, a single approval merges it.
- Severity: HIGH
- Likelihood: MEDIUM (insider risk, not external)

### R-2  Webhook secret leakage
A literal Slack/Teams webhook in `aios.yml` is effectively a public bearer token —
anyone with the file can post messages as the bot.
- Severity: HIGH
- Likelihood: HIGH if not detected at PR time

### R-3  CI breakage from new fail-closed enforcement
Existing repos run `aios suppress` / `aios override-gate` from CI without an actor
identity. Turning enforcement on would break every release pipeline overnight.
- Severity: HIGH (release blockers)
- Likelihood: HIGH if rolled out without staged migration

### R-4  Notification storm on baseline replay
First scan after enabling notifications could fan out hundreds of HIGH alerts for
findings that already existed pre-feature.
- Severity: MEDIUM (alert fatigue, pager noise)
- Likelihood: HIGH on first run

### R-5  Audit log corruption silently breaks chain
Manual edits or filesystem corruption breaks the hash chain. If we don't surface
the break, the audit feature becomes theatre.
- Severity: MEDIUM (compliance evidence)
- Likelihood: LOW

### R-6  SMTP/webhook outage masks real findings
Best-effort delivery means a Slack outage during a real CRITICAL silently drops
the only signal the team would have seen.
- Severity: MEDIUM
- Likelihood: LOW

### R-7  False sense of authorization
Teams may treat AIOS permissions as an access-control boundary equivalent to
GitHub branch protection or AWS IAM. It is not — it only gates AIOS CLI actions.
- Severity: MEDIUM (governance misunderstanding)
- Likelihood: MEDIUM

## Mitigations

| Risk | Mitigation |
|------|------------|
| R-1  | CODEOWNERS lock on `permissions:` block + G-NEW-PERMS-DRIFT detector requires `aios-permissions-reviewed` label on the PR. |
| R-2  | G-NEW-NOTIFY-PLAINTEXT detector runs on every scan, severity HIGH, blocks the gate. Migration script `aios notify-migrate` extracts literals to a secret reference. |
| R-3  | Two-phase rollout: phase 1 `permissions.enforce: warn` (logs would-be-denials), phase 2 (≥ 2 weeks later) `enforce: deny`. CI templates updated in phase 1. |
| R-4  | Baseline mode on first run: `aios scan --baseline-mode` emits zero notifications and snapshots current findings; notifications fire only on *new* findings vs. snapshot. |
| R-5  | `aios audit-tail --verify` re-walks the chain on every CI run; broken chain => non-zero exit + visible CRITICAL banner. |
| R-6  | At least 2 channels required when `severity_min <= HIGH`; validator enforces. Email + Slack covers single-channel outages. |
| R-7  | Doc clearly states "AIOS permissions are *additional*, not a substitute for IAM/branch-protection"; SECURITY.md updated. |

## Open Questions
- OQ-1  Should `admin` role be assignable per-repo or only globally? Suggest globally
        in v1; per-repo adds matrix complexity.
- OQ-2  GitHub PR comment channel — bot identity reuse `aios-bot` GH App or per-repo PAT?
        Pending answer from BO-AMX platform team.
- OQ-3  Is the audit log retention requirement 90 d or 7 y? SOX scope (SICOFAV) implies 7 y;
        non-SOX repos likely 90 d. Need per-repo config.
- OQ-4  Where does `AIOS_OIDC_CLAIMS_JSON` come from in self-hosted runners?
        GitHub Actions provides it natively; CodeBuild / Azure DevOps need a shim.
- OQ-5  Do we want to integrate with existing AMX ServiceNow change-record tooling
        for `override-gate`, or is the AIOS audit log enough? Defer to v2.
