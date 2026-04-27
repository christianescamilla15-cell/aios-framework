# Feature - Add notifications and permissions

## Rollout Plan

Two-phase, opt-in then default-on. No big-bang.

- **Phase 0 — Land code, default OFF.**
  Ship the feature behind missing-block-means-no-op semantics. Existing repos see
  zero behaviour change.

- **Phase 1 — `enforce: warn` + dry-run notifications.**
  Pilot apps (SICOFAV, NoShow) opt in by adding `permissions:` and `notifications:`
  to their `aios.yml`. Enforcement is `warn`: privileged actions still execute but
  log a `would-deny` audit entry. Notifications run in `--dry-run` (rendered to
  CI log only). Duration: 2 weeks min.

- **Phase 2 — `enforce: deny` + live notifications.**
  Flip pilot apps to `enforce: deny` and remove `--dry-run`. Confirm zero CI
  breakage in Phase 1 audit log before flipping. Then onboard remaining apps
  one by one (Robot, SRG, BSP, ARC, ASR, Com-D, Com-I, CFDIs).

- **Phase 3 — Default-on for new repos.**
  `aios init` scaffolds `permissions:` + `notifications:` with sensible defaults
  (admin = repo creator, channel = stdout). Existing repos remain opt-in.

## Deployment Steps
1. Tag `vX.Y.0` on `main` after T1–T8 pass; push to `origin` and `amx`.
2. Update `BACKLOG.md`: move N+P items from "active" to "shipped"; reference tag.
3. Open one PR per pilot app adding `permissions:` + `notifications:` blocks
    with `enforce: warn`. Get app owner + sec lead to merge.
4. Announce in #aios-framework Slack: link to docs/NOTIFICATIONS_AND_PERMISSIONS.md,
    list of pilot apps, opt-in instructions, expected Phase 2 date.
5. Schedule a recurring agent (`/schedule`) to run weekly during Phase 1 that
    `aios audit-tail --since 7d --filter would-deny` and reports counts —
    confirms whether flipping to `deny` is safe.
6. After 2 weeks of green Phase 1, open PRs flipping pilots to `enforce: deny`.
7. Onboard remaining 8 apps in batches of 2/week.

## Post-Deploy Checks
- [ ] Main flow works: scan with synthetic CRITICAL fires Slack + email on pilot.
- [ ] Logs healthy: no unhandled exceptions in notification path; warnings only on
      simulated channel failure.
- [ ] `aios audit-tail --verify` exits 0 on every pilot's first 100 actions.
- [ ] No regression in finding counts across 4 baseline apps vs. pre-tag.
- [ ] Throttle dedup: deliberately re-trigger same finding within window — exactly
      one delivered message recorded.
- [ ] Permission denied: viewer attempts `suppress` on pilot, gets non-zero exit
      with explicit error, audit log records the attempt.
- [ ] G-NEW-NOTIFY-PLAINTEXT: PR introducing a literal webhook URL is blocked at gate.
- [ ] G-NEW-PERMS-DRIFT: PR editing `permissions.users[]` without admin label is blocked.
- [ ] Rollback drill: revert tag in a sandbox repo, confirm `aios scan` still works
      and no orphaned `.aios/throttle.db` / `audit.log` cause errors.
- [ ] Docs published: `docs/NOTIFICATIONS_AND_PERMISSIONS.md` + updated `SECURITY.md`
      ("AIOS permissions are additional to, not a substitute for, IAM/branch protection").
