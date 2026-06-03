# uvoo-certctl v0.4.0

Adds subject auto-approval, richer auth debugging, better metrics access controls, and stronger auth observability without expanding the core model much.

## Highlights

- Subject auto-approval rules for JWT/OIDC users with issuer-scoped matching on email domain, upstream roles, and upstream groups.
- Local subject lifecycle and assignment improvements, including `update-subject` and better filtering/reporting for locally tracked users.
- Expanded auth provider presets for `keycloak`, `microsoft-tenant`, and `aws-cognito`.
- Optional dedicated Basic auth credentials for `/metrics`, separate from the admin API credentials.
- Stronger auth observability with auth outcome counters, subject auto-approval match counters, and explicit pending-subject metrics.
- Better bearer-token debugging through richer `explain-authz` and `list-effective-authz` output.

## Operator-focused improvements

- New subject auto-approval rules can automatically activate first-seen JWT subjects and assign local roles or groups without introducing a larger policy engine.
- `explain-authz` and `list-effective-authz --bearer-token ...` now show local subject status, matching auto-approval rules, and the predicted local assignments and effective access state for a token.
- `/metrics` can now use its own Basic auth credentials with `--metrics-username` and `--metrics-password`, which is helpful when metrics need a fallback path without exposing the full admin password.
- Metrics now include low-cardinality auth and subject signals such as:
  - `uvoo-certctl_auth_requests_total`
  - `uvoo-certctl_subject_auto_approval_matches_total`
  - `uvoo-certctl_pending_subjects_total`
  - `uvoo-certctl_pending_subjects_older_than_days_total`
- The Docker Keycloak smoke stack now exercises first-login subject auto-approval by default and supports easier manual debugging with `--skip-cleanup` and `--only-cleanup`.

## Included artifacts

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`
- `windows/arm64`

## Upgrade notes

- Existing SQLite databases continue to migrate automatically on open.
- JWT subjects still default to `pending` unless they match a configured auto-approval rule.
- Existing admin Basic auth and bearer-auth flows continue to work.
- `/metrics` now accepts a dedicated Basic auth pair when configured; otherwise it continues to use the admin Basic auth or bearer auth path.
- `doctor` and `/metrics` may surface more auth-related warnings and counters than earlier releases because subject auto-approval and pending-subject tracking are now first-class operational signals.
