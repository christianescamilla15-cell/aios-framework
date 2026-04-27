# Feature - Add notifications and permissions

## Current State
- Scan results are written to stdout and `.aios/findings.json`. No push channel.
- Any user with shell access to the repo can run `aios suppress`, `aios override-gate`,
  `aios publish-baseline`. There is no role check.
- Waivers are added by editing `aios.yml` directly; reviewer is a social convention,
  not enforced.
- Audit trail is git history of `aios.yml`; no structured audit log of privileged
  CLI actions.

## Proposed Design

### Module layout
```
aios/
  notifications/
    __init__.py
    config.py        # parse + validate `notifications:` block
    router.py        # finding -> list[Channel] based on rules
    channels/
      base.py        # Channel ABC: send(payload) -> Result
      stdout.py
      file.py
      email_smtp.py
      webhook.py     # generic JSON POST (Slack/Teams compatible)
      github_pr.py   # uses GH_TOKEN
    formatters/
      slack.py
      email_html.py
      github_md.py
    throttle.py      # SQLite-backed dedup + digest window
  permissions/
    __init__.py
    model.py         # Role enum, Action enum, role >= action matrix
    resolver.py      # who am i? -> file | env | OIDC claim
    enforcer.py      # decorator @requires(Action.SUPPRESS)
    audit.py         # append-only hash-chained JSONL writer
```

### Data flow (notification)
```
scan() -> findings[]
       -> router.route(findings, config) -> [(channel, payload), ...]
       -> throttle.filter(...) -> [(channel, payload), ...]
       -> for each: channel.send(payload) (best-effort, errors -> warn log)
```

### Data flow (permission check)
```
CLI subcommand entry
  -> resolver.current_actor()  (env AIOS_ACTOR or git config user.email or OIDC sub)
  -> enforcer.check(actor, Action.X)
     -> resolve actor's role from aios.yml -> permissions.users[]
     -> Role.has(Action.X)? -> raise PermissionDenied if not
  -> on success: audit.append({actor, action, target, ts, justification})
  -> proceed with action
```

### Config schema (additions to `aios.yml`)
```yaml
notifications:
  channels:
    slack-sec:
      type: webhook
      url_secret: op://Security/aios-slack/url   # secret reference, never literal
      format: slack
    email-oncall:
      type: email_smtp
      host_secret: env://SMTP_HOST
      to: ["sec-oncall@bo-amx.local"]
      format: email_html
  rules:
    - app: sicofav
      severity_min: HIGH
      channels: [slack-sec, email-oncall]
    - detector: G-NEW-NOTIFY-PLAINTEXT
      severity_min: ANY
      channels: [slack-sec]
  throttle:
    window_minutes: 60
    digest: true

permissions:
  users:
    - email: christianescamilla15@gmail.com
      role: admin
    - email: amontielv_amx@bo-amx.local
      role: reviewer
    - email: gmagallanes_amx@bo-amx.local
      role: developer
  oidc:
    enabled: false
    role_claim: aios_role
```

### Role / Action matrix
| Action            | viewer | developer | reviewer | admin |
|-------------------|:------:|:---------:|:--------:|:-----:|
| scan / report     |   y    |     y     |    y     |   y   |
| suppress finding  |   -    |     -     |    y     |   y   |
| override gate     |   -    |     -     |    y     |   y   |
| publish baseline  |   -    |     -     |    y     |   y   |
| edit detector     |   -    |     -     |    -     |   y   |
| edit permissions  |   -    |     -     |    -     |   y   |

## Architecture Impact
- New optional dependency: `requests` (webhook) — already transitively present.
- New optional dependency: SMTP via stdlib `smtplib` (no new dep).
- `aios.yml` schema bumps `version` from `1` to `2`; loader stays back-compatible
  (missing `notifications:` / `permissions:` blocks => no notifications, no enforcement,
  matches today's behaviour).
- New CLI subcommands: `aios notify`, `aios whoami`, `aios audit-tail`.
- New detector: G-NEW-NOTIFY-PLAINTEXT (urls/secrets in `notifications:` must be `op://`,
  `env://`, `aws-sm://` references, never literal).

## Tradeoffs
- **File-backed permissions vs. external IdP.** File is simpler, works offline, fits
  the current AMX scope where AIOS is run from CI and dev laptops. Tradeoff: anyone
  with write access to `aios.yml` can self-promote. Mitigation: G-NEW-PERMS-DRIFT
  detector flags edits to `permissions.users[]` and requires review label on PR;
  CODEOWNERS can lock that block.
- **Best-effort delivery vs. guaranteed.** A failed Slack post must not block a CI gate
  (we already had an incident where flaky webhook stopped releases). Tradeoff: a real
  outage is silent on Slack — covered by digest fallback to email.
- **Throttle in SQLite vs. in-memory.** SQLite survives across `aios` invocations in CI,
  in-memory does not. Cost: one extra file (`.aios/throttle.db`) gitignored.
- **Hash-chained audit log vs. plain JSONL.** Hash chain costs ~5 lines, deters silent
  edits, fits SOX expectations from SICOFAV. Worth it.

## Risks
See risks.md.
