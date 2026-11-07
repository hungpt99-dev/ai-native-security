# Operations runbook

## Starting the stack

```bash
cp .env.example .env            # set ANS_SECRET_KEY at minimum
docker compose up --build -d
docker compose ps
docker compose logs -f api worker scheduler
```

`migrate` runs `alembic upgrade head` and must exit 0 before `api`, `worker` and
`scheduler` start. If it fails, the API keeps restarting; inspect
`docker compose logs migrate`.

## Verifying a deployment

```bash
curl -fsS localhost:8000/healthz
curl -fsS localhost:8000/readyz
curl -fsS localhost:8000/api/v1/system/scanners
```

`/system/scanners` should report `available: true` for `trivy`, `semgrep`,
`gitleaks` and `syft`. A missing binary appears as `SKIPPED` executions and does
**not** fail scans, but a scanner that is present and crashes does.

## Scaling

* Workers: `docker compose up -d --scale worker=3`. Jobs are claimed with
  `SKIP LOCKED`; each worker handles one job at a time (scanners are CPU-heavy,
  so prefer more containers over more threads).
* API: the compose service already runs 2 uvicorn workers; scale horizontally
  behind nginx for heavier dashboard use.
* Scheduler: keep exactly one. An advisory lock makes extra instances exit
  immediately, so a duplicate does no harm.

## Data retention

| Data | Where | Suggested retention |
| --- | --- | --- |
| `scans`, `scanner_executions` | PostgreSQL | 90 days (`DELETE FROM scans WHERE created_at < now() - interval '90 days'`) |
| `findings` | PostgreSQL | keep (history matters); resolved findings are cheap |
| `finding_history` | PostgreSQL | keep, or prune by age |
| `sboms` rows + files | PostgreSQL + storage volume | 30–90 days; delete the row **and** the object. Never update a snapshot row — delete whole snapshots only |
| `sbom_monitoring_runs` | PostgreSQL | 90 days (aggregates stop being meaningful after that) |
| `webhook_deliveries` | PostgreSQL | 30 days (idempotency window) |
| `jobs` (SUCCEEDED/FAILED) | PostgreSQL | 14 days |
| `vulnerability_sync_history` | PostgreSQL | 30 days |

Deleting a `scan` sets `findings.first_scan_id/last_scan_id` to NULL
(`ON DELETE SET NULL`), so retention never deletes findings by accident.
Deleting an asset cascades to its scans, findings, SBOMs and packages.

## Backups

```bash
docker compose exec -T postgres pg_dump -U security security | gzip > backup-$(date +%F).sql.gz
docker run --rm -v ai-native-security_sbom-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/sboms-$(date +%F).tar.gz -C /data .
```

Restore in the reverse order (database first, then the volume), then run
`alembic upgrade head` to be sure the schema matches the running image.

## SBOM lifecycle operations

Three operations, three budgets:

| Operation | Schedule (default) | Cost | What it proves |
| --- | --- | --- | --- |
| `SCAN` | `ANS_SCANNER_SCHEDULE_INTERVAL_MINUTES` (240) | clone + Syft + Trivy/Semgrep/Gitleaks | composition **and** source-code issues |
| `SBOM_CHANGE_CHECK` | `ANS_SBOM_DEPENDENCY_CHECK_INTERVAL_MINUTES` (60) | provider API / `git ls-remote` only | whether composition changed |
| `SBOM_GENERATE` | on demand (webhook/check/manual) | clone + Syft | a new immutable snapshot |
| `SBOM_VULNERABILITY_REASSESSMENT` | `ANS_SBOM_REASSESSMENT_INTERVAL_MINUTES` (1440) | database only | whether stored inventory is affected by current intel |

Configuration:

```bash
ANS_SBOM_MONITORING_ENABLED=true
ANS_SBOM_DEPENDENCY_CHECK_INTERVAL_MINUTES=60
ANS_SBOM_REASSESSMENT_INTERVAL_MINUTES=1440
ANS_SBOM_MAX_REASSESSMENT_COMPONENTS=5000   # ceiling per snapshot
ANS_SBOM_REASSESS_AFTER_INTEL_SYNC=true     # reassess when a feed changes something
ANS_WEBHOOK_SECRET=...                      # enables /webhooks/*, otherwise 503
```

Webhooks (recommended over polling):

* GitHub: *Settings → Webhooks → Add webhook*, payload URL
  `https://<host>/api/v1/webhooks/github`, content type `application/json`,
  secret = `ANS_WEBHOOK_SECRET`, events: **push only**.
* GitLab: *Settings → Webhooks*, URL `https://<host>/api/v1/webhooks/gitlab`,
  secret token = `ANS_WEBHOOK_SECRET`, trigger: **Push events**.
* Deliveries are recorded in `webhook_deliveries`; a repeated `X-GitHub-Delivery`
  (or GitLab event UUID) is answered with `DUPLICATE` and enqueues nothing.

### Routine SBOM checks

| Question | Query / endpoint |
| --- | --- |
| Is composition monitoring running? | `GET /api/v1/schedules` → `asset-sbom-check:*`, `sbom:reassess` have a moving `next_run_at` |
| Did monitoring skip full scans? | `GET /api/v1/sbom/monitoring/summary?days=7` → `estimated_full_scans_avoided`, `dependency_checks_unchanged` |
| Which assets are stale or unknown? | `GET /api/v1/assets/{id}/sbom/status` → `freshness`, `freshness_detail` |
| Did an evaluation fail? | `GET /api/v1/assets/{id}/sbom/monitoring-runs?kind=VULNERABILITY_REASSESSMENT&status=FAILED` |
| Are findings coming from stored inventory? | `select discovery_source, count(*) from findings group by 1` |
| Webhook health | `select action, count(*) from webhook_deliveries group by 1` |

```sql
-- assets whose latest evaluation did not succeed
select asset_id, status, error_message, finished_at
from sbom_monitoring_runs
where kind = 'VULNERABILITY_REASSESSMENT'
  and status in ('FAILED','PARTIAL')
order by started_at desc limit 20;

-- avoidable full scans: dependency checks that proved composition unchanged
select count(*) from sbom_monitoring_runs
where kind = 'DEPENDENCY_CHECK'
  and outcome in ('UNCHANGED','NO_DEPENDENCY_CHANGE');
```

Guidance:

* Do **not** lower `SBOM_VULNERABILITY_REASSESSMENT` below the feed cadence — it
  only finds what the feeds already ingested.
* If `freshness` stays `UNKNOWN`, the provider API and `git ls-remote` both
  failed: fix egress/credentials rather than forcing snapshots, so the platform
  stops claiming it cannot tell.
* `PARTIAL` reassessments are not errors but they intentionally block
  auto-resolution. Read `metrics.resolution_reasons` before assuming a finding
  is stuck.

## Routine checks

* `GET /api/v1/dashboard/summary` → `scans.failed_last_24h`,
  `failing_assets`, `scans.active`.
* `GET /api/v1/jobs?status=FAILED` → `last_error` shows why a job failed.
* `GET /api/v1/vulnerabilities/sync/history` → freshness per feed; NVD/KEV
  should be < 24h, OSV < 12h by default.
* `GET /api/v1/schedules` → `next_run_at` should move forward, `last_status`
  should not be stuck on `SKIPPED`.

## AI configuration and budget

AI is off until you configure a provider:

```bash
ANS_AI_ENABLED=true
ANS_AI_PROVIDER=openai            # any OpenAI-compatible endpoint
ANS_AI_BASE_URL=https://api.openai.com/v1
ANS_AI_MODEL=gpt-4.1-mini
ANS_AI_API_KEY=sk-...
ANS_AI_DAILY_BUDGET_USD=5
# Gateways that need routing headers (single-quote the JSON!):
# ANS_AI_EXTRA_HEADERS='{"x-session":"ai-native-security"}'
```

Verify:

```bash
curl -s localhost:8010/api/v1/ai/health | jq
# enabled/configured/model + budget.cost_usd_today + budget.executions_today
```

Checks worth running in production:

| Check | Query / endpoint |
| --- | --- |
| spend today | `GET /api/v1/ai/health` → `budget.cost_usd_today` |
| failures by code | `GET /api/v1/ai/executions?status=FAILED` |
| rate limiting | `GET /api/v1/ai/executions?status=RATE_LIMITED` |
| invalid model output | `GET /api/v1/ai/executions?status=INVALID_OUTPUT` |
| deterministic-only assessments | `select count(*) from risk_assessments where deterministic_only` |
| unverified proposals | `select count(*) from remediation_recommendations where status in ('AWAITING_APPROVAL','APPROVED')` |

Operational rules:

* A budget of `0` disables the hard stop (not recommended). The default is `5`.
* Auto-analysis after a scan is bounded by `ANS_AI_AUTO_ANALYZE_MAX_FINDINGS` (10)
  and `ANS_AI_AUTO_ANALYZE_MIN_SEVERITY` (`HIGH`); raise deliberately.
* If the provider is down, scans still complete; assessments are stored as
  `deterministic_only` and are visibly labelled in the UI.
* EPSS refresh (`SYNC_EPSS`, daily) needs outbound access to the FIRST feed; a
  failure keeps the previous scores and is recorded in `vulnerability_sync_history`.
* Rotating `ANS_AI_MODEL` is safe: every assessment records the model and prompt
  version it was produced with.

## Troubleshooting

### Scan stuck in RUNNING

The worker died mid-scan. Jobs are reaped after
`ANS_JOB_STALE_AFTER_SECONDS` (default 1h) and retried; to force it:

```sql
UPDATE jobs SET heartbeat_at = now() - interval '2 hours', status = 'RUNNING'
WHERE status = 'RUNNING';
-- then restart the worker; recover_stale_jobs() requeues it
```

The scan row itself is left `RUNNING` if the process was killed; re-triggering
the asset is blocked by the "one active scan" rule, so cancel it first:
`POST /api/v1/scans/{id}/cancel`.

### Trivy: "failed to download vulnerability DB"

First run downloads ~1 GB into the `trivy-cache` volume. Check egress,
`ANS_SCANNER_MAX_FILE_SIZE_MB` (raise to 4096+ if the DB write fails) and disk
space on the worker. Pre-seed the cache in CI or from a warm volume.

### Semgrep: "engine was killed" / no results

Semgrep needs memory proportional to rules × files. Keep `ANS_SEMGREP_JOBS` low
(default 2) on small VPS instances and raise `ANS_SCANNER_MAX_MEMORY_MB` if
needed. A partial run still records findings; the tool error is surfaced in
`scanner_executions.error_message`.

### Semgrep finds nothing

`ANS_SEMGREP_CONFIG` defaults to the registry ruleset `p/security-audit`, which
requires network access on first use. For air-gapped deployments mount a local
rules directory and point `ANS_SEMGREP_CONFIG` at it.

### OSV returns HTTP 400

Usually one package carries an ecosystem name OSV does not know. The client
filters unsupported ecosystems and splits failing batches until the offending
query is isolated; the package is logged as a warning and skipped.

### Clone fails for a private repository

Confirm the token is valid for that host and has read access. GitLab tokens are
sent as `oauth2:<token>`, GitHub as `x-access-token:<token>`. Re-save the token
(`PUT /assets/{id}` with `access_token`) if `ANS_SECRET_KEY` changed — old
ciphertext becomes unreadable and clones fail with an authentication error.

### "A scan is already pending or running for this asset"

A partial unique index enforces one active scan per repository. Wait for it, or
`POST /api/v1/scans/{id}/cancel` and retry.

### Findings were not auto-resolved

By design: resolution only happens for scans that completed with **no** failed
or timed-out scanner. If a scanner is unhealthy, old findings stay open until a
clean scan runs.

For reassessment the rule is stricter: a finding is resolved only when the exact
installed version is still inventoried and stored ranges exclude it, or when the
snapshot proves the package/version left the composition **and** the finding
carries inventory provenance. A missing intelligence record, an unusable range
(`GIT` events) or a truncated inventory never resolves anything.

### SBOM freshness is UNKNOWN

`UNKNOWN` means "not verified", not "broken". Common causes:

1. no dependency check has run since the snapshot was generated (wait for the
   hourly schedule or `POST /assets/{id}/sbom/check`);
2. the provider API and `git ls-remote` both failed (egress, private repo token,
   provider outage) — the run is stored as `PARTIAL` with `error_message`;
3. the compare payload named the base commit as unreachable (force-push) — the
   composition state cannot be derived, so nothing is claimed.

### "A snapshot with this fingerprint and commit already exists"

The partial unique index rejected a concurrent duplicate generation. The job is
recorded as `SKIPPED`/`duplicate_snapshot`; this is the intended outcome, not an
error. Full scans are exempt (each scan owns its artifact).

### Reassessment says PARTIAL

Either the inventory exceeded `ANS_SBOM_MAX_REASSESSMENT_COMPONENTS`, or some
components had intelligence whose ranges cannot be evaluated for a version
(GIT-only ranges, unparseable versions). The run stores `failure_count`,
`unknown_evaluations` and `resolution_reasons`; resolutions are skipped
deliberately. Raise the ceiling or accept missing evidence — never lower the bar
by resolving on absence.

## Troubleshooting: AI

| Symptom | Cause | Fix |
| --- | --- | --- |
| `/ai/health` shows `configured: false` | no key, or `ANS_AI_ENABLED=false` | set both, restart api/worker |
| `503 ai_unavailable` on a mutation | AI disabled or severity gate excluded the finding | expected; deterministic results still exist |
| `ai_provider_error` with 400 | gateway rejected `response_format` or the model name | the provider falls back to `json_object` once; check `ANS_AI_MODEL` |
| assessments all `deterministic_only` | every call failed | inspect `GET /ai/executions?status=FAILED` and the worker logs |
| `ai_budget_exceeded` | daily budget reached | raise `ANS_AI_DAILY_BUDGET_USD` or wait for the next UTC day |
| empty completions (`INVALID_OUTPUT`, `finish_reason=length`) | reasoning model spent the token budget | raise `ANS_AI_MAX_OUTPUT_TOKENS` |
| assistant refuses / returns gaps | no matching rows in the data | check the tool results in the transcript; the answer is grounded, not guessed |

## Upgrading

```bash
git pull
docker compose build
docker compose run --rm migrate            # migrations first
docker compose up -d
```

Migrations are additive; always take a backup before upgrading across revisions.

For the SBOM lifecycle revision (`2cf7e16e149a`):

* existing snapshots are backfilled with `creation_reason='FULL_SCAN'`,
  `generation_status='READY'` and `generated_at=created_at`;
* `commit_sha` and the fingerprints stay `NULL` for those rows — they were not
  recorded, and inventing them would be worse than admitting the gap. The first
  new snapshot (or full scan) establishes the baseline;
* the downgrade deletes schedules for the three new job kinds (their payloads
  are meaningless to older code) and drops the new columns/tables; snapshot rows
  and documents themselves are untouched.

## Runtime security operations

### 1. Enable telemetry ingestion

```bash
# .env
ANS_EVENTS_INGEST_TOKEN=$(openssl rand -hex 32)
ANS_EVENTS_AUTO_CREATE_ASSETS=true
```

Recreate the API and worker so both read the token. Verify:

```bash
curl -s localhost:8000/api/v1/ingest/health
# {"configured":true,"max_batch":500}
```

Point Falco at `/api/v1/ingest/falco` with the token header (see
`RUNTIME_SECURITY.md`). A quick smoke test:

```bash
curl -s -X POST localhost:8000/api/v1/ingest/falco \
  -H "X-ANS-Ingest-Token: $ANS_EVENTS_INGEST_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"uuid":"smoke-1","priority":"Warning","rule":"Terminal shell in container",
       "output":"shell","output_fields":{"proc.name":"bash",
       "container.image.repository":"ghcr.io/acme/api","container.image.tag":"1.0"}}'
```

Expected: `202`, `created: 1`, one container asset auto-created, and the event
visible at `/api/v1/events`.

### 2. Triage an incident

1. `GET /incidents?active_only=true&sort_by=risk_score` — highest deterministic
   risk first.
2. `GET /incidents/{id}` — read the timeline, attached events, linked findings.
3. `PATCH /incidents/{id}` → `TRIAGING` / `INVESTIGATING` with a note.
4. `POST /incidents/{id}/correlate` to pull same-asset events (±24 h) and
   same-CVE findings across assets.
5. `POST /incidents/{id}/investigate` for an AI explanation. It is evidence, not
   a decision: review cited keys and missing information before acting.
6. `CONTAINED` → `RESOLVED` when the evidence supports it, then `CLOSED`.
   Reopening is allowed and recorded.

There is no automatic containment. Containment actions in the AI report are
recommendations for a human.

### 3. Interpret monitoring health

`GET /monitoring/health` reports `HEALTHY`, `DEGRADED`, `UNKNOWN` or `DISABLED`
per control. `UNKNOWN` means "no evidence yet", not "fine".

| Component | `DEGRADED` means | First check |
| --- | --- | --- |
| `repository_monitoring` | stale or failed last scans | `/assets`, `/scans?status=FAILED` |
| `sbom_monitoring` | no check within 2× interval, or failures in 24 h | `/sbom/monitoring/summary` |
| `threat_intelligence` | a source is older than its window | `/intelligence/sync-history` |
| `event_ingestion` | no event for > 60 min (while configured) | sensor connectivity, token |
| `job_queue` | failed jobs in 24 h or > 500 queued | `docker compose logs worker` |
| `infrastructure` | failed assessments in 24 h | `/infrastructure/scans?status=FAILED` |

### 4. Infrastructure assessments

```bash
# container image (registry must be allowlisted)
curl -s -X POST localhost:8000/api/v1/infrastructure/scans \
  -H 'Content-Type: application/json' \
  -d '{"target_kind":"CONTAINER_IMAGE","scanner":"trivy-image","target_ref":"ghcr.io/acme/api:1.2.3"}'

# IaC repository
curl -s -X POST localhost:8000/api/v1/infrastructure/scans \
  -H 'Content-Type: application/json' \
  -d '{"target_kind":"IAC_REPOSITORY","scanner":"trivy-config","asset_id":"<repo-uuid>"}'
```

The worker clones (IaC only), runs the scanner in the hardened subprocess layer,
writes findings through the normal pipeline, and deletes the workspace. Check
`/infrastructure/scanners` first: a missing binary is reported as unavailable, not
as an empty scan. Enable Checkov by building the worker with
`INSTALL_CHECKOV=true`.

### 5. Rotate tokens and retention

* Rotate `ANS_EVENTS_INGEST_TOKEN` by updating `.env`, recreating API/worker, then
  updating sensors. Old tokens stop working immediately.
* Rotating `ANS_SECRET_KEY` invalidates stored repository credentials; re-enter
  tokens after rotation.
* Event and audit tables grow monotonically. Schedule a retention job appropriate
  to your policy, for example:

```sql
DELETE FROM security_events
WHERE last_seen_at < now() - interval '180 days'
  AND incident_id IS NULL
  AND status = 'CLOSED';
```

Never delete audit rows inside the retention window your compliance policy
requires. Back up before deleting.

### 6. Backup and restore

The database is the system of record; SBOM documents live under
`ANS_STORAGE_ROOT` (or the `sbom-data` volume). Back up both:

```bash
docker compose exec -T postgres pg_dump -U security security | gzip > backup-$(date +%F).sql.gz
docker run --rm -v ai-native-security_sbom-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/sboms-$(date +%F).tar.gz -C /data .
```

Restore into a fresh PostgreSQL, run `alembic upgrade head`, restore the SBOM
volume, then start worker/scheduler. Verify with `/readyz`, `/monitoring/health`
and a scan of one repository.
