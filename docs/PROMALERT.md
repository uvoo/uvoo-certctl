# promalert

`promalert` is a small companion watchdog for `uvoocertctl` and other Prometheus-style metric endpoints.

It stays intentionally small:

- scrape one or more `/metrics` endpoints directly
- match simple metric threshold rules or raw regex rules
- notify to `stdout`, generic webhooks, native PagerDuty Events API v2, or SMTP email
- dedupe alerts in memory and send a resolved event when the condition clears

It does not try to replace Prometheus Alertmanager.

## Run it

From the repo:

```bash
go run ./cmd/promalert --config promalert.yaml
go run ./cmd/promalert --config promalert.yaml --state-file promalert-state.json
go run ./cmd/promalert --config promalert.yaml --check-config
go run ./cmd/promalert --config promalert.yaml --once
go run ./cmd/promalert --check-config promalert.yaml
```

By default, `promalert` stores active alert state in `promalert-state.json` so it can avoid retriggering the same firing alerts immediately after a restart. Set `--state-file ''` to disable persistence.

## Config

Example:

```yaml
interval: 60s
default_timeout: 10s
default_cooldown: 15m

targets:
  - name: uvoocertctl-prod
    url: https://uvoocertctl.example.com:8443/metrics
    headers:
      X-Org-ID: engineering
    basic_auth:
      username: metrics
      password: env:CERTCTL_METRICS_PASSWORD

  - name: uvoocertctl-staging
    url: https://uvoocertctl-staging.example.com:8443/metrics
    enabled: false

notifiers:
  - name: stdout
    type: stdout

  - name: ops-webhook
    type: webhook
    url: env:PROMALERT_WEBHOOK_URL
    timeout: 5s
    headers:
      Authorization: env:PROMALERT_WEBHOOK_AUTH

  - name: pagerduty
    type: pagerduty
    routing_key: env:PROMALERT_PAGERDUTY_ROUTING_KEY
    source: uvoocertctl-prod
    severity: critical
    dedup_key_prefix: uvoocertctl

  - name: email
    type: smtp
    smtp_host: smtp.sendgrid.net
    smtp_port: 587
    smtp_username: apikey
    smtp_password: env:PROMALERT_SMTP_PASSWORD
    smtp_from: alerts@example.com
    smtp_to:
      - ops@example.com
    subject_prefix: "[promalert]"

rules:
  - name: pending-private-csrs
    metric: uvoocertctl_pending_csr_requests_total
    labels:
      kind: private
    op: gt
    value: 0
    notify:
      - stdout
      - pagerduty
      - email

  - name: stale-pending-subjects
    metric: uvoocertctl_pending_subjects_older_than_days_total
    labels:
      days: "30"
    op: gt
    value: 0

  - name: auth-issuer-connectivity-errors
    metric: uvoocertctl_auth_issuers_connectivity_status_total
    labels:
      status: error
    op: gt
    value: 0

  - name: auth-doctor-errors
    metric: uvoocertctl_doctor_findings_total
    labels:
      severity: error
    op: gt
    value: 0

  - name: metrics-body-regex
    regex: 'uvoocertctl_auth_requests_total\{.*result="invalid".*\} [1-9][0-9]*'
```

## Secret references

Like `uvoocertctl`, string fields support:

- raw values
- `env:VARNAME`
- `file:/path/to/secret`

That works for:

- target URLs
- target headers
- target basic auth usernames and passwords
- webhook URLs
- webhook headers
- pagerduty routing keys
- smtp usernames, passwords, and sender addresses

## Rule model

Metric rules support:

- `metric`
- exact-match `labels`
- `op`: `gt`, `gte`, `lt`, `lte`, `eq`, `ne`, `absent`
- `value`

Regex rules support:

- `regex`

Rules can optionally target a subset of scrape targets with:

```yaml
targets:
  - uvoocertctl-prod
```

Rules can optionally route only to selected notifiers with:

```yaml
notify:
  - ops-webhook
```

If no `notifiers` section is provided, `promalert` creates a default `stdout` notifier automatically.

If a rule explicitly references `stdout`, `promalert` also adds an implicit `stdout` notifier automatically even when you define PagerDuty, SMTP, or webhook notifiers yourself.

## Notifications

Each notification is a small JSON payload with:

- `status`: `firing` or `resolved`
- `target`
- `rule`
- `metric`
- `labels`
- `value`
- `message`
- `timestamp`

Webhook notifiers send the raw `promalert` event JSON as-is.

PagerDuty notifiers send Events API v2 payloads directly:

- `firing` maps to `event_action: trigger`
- `resolved` maps to `event_action: resolve`
- dedup keys default to `<prefix>:<target>:<rule>`

SMTP notifiers send a plain-text email with:

- a short subject line
- the event message
- the full event JSON in the body

## Persistent state

`promalert` stores only a tiny amount of state:

- currently firing alerts
- last notification timestamp
- notifier names used for that alert

It does not store full metric history or raw scrape data.

This lets it:

- avoid duplicate firing notifications on restart
- keep cooldown behavior consistent across restarts
- still send a `resolved` notification when the condition clears later
