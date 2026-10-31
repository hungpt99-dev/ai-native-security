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
| `sboms` rows + files | PostgreSQL + storage volume | 30–90 days; delete the row **and** the object |
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

Migrations are additive in Phase 1; always take a backup before upgrading across
revisions.
