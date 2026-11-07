# API reference

Base path: `/api/v1`. Interactive docs: `/docs` (Swagger UI) and `/redoc`.
OpenAPI JSON: `/openapi.json`.

## Conventions

* JSON in/out, `snake_case` fields, UUIDs as strings, timestamps ISO-8601 UTC.
* List endpoints accept `page` (1-based) and `page_size` (max 200) and return
  `{items, total, page, page_size, pages}`.
* Multi-value filters repeat the query parameter: `severity=CRITICAL&severity=HIGH`.
* Errors use one envelope:
  ```json
  {"error": {"code": "conflict", "message": "Repository is already registered",
             "details": {"repo_url": "https://github.com/o/r"}}}
  ```
  Codes: `validation_error` (422), `not_found` (404), `conflict` (409),
  `unauthorized` (401), `forbidden` (403), `scanner_unavailable` (503),
  `external_service_error` (502), `database_error`/`internal_error` (500).
* Authentication is optional for local development. With
  `ANS_AUTH_ENABLED=true`, send `X-API-Key: <key>` on every request; missing or
  wrong keys return 401. Authentication is enforced at router level, so no
  endpoint is exempt.

## Health

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/healthz` | liveness, no DB |
| GET | `/readyz` | readiness, pings PostgreSQL |

## Assets

| Method | Path | Description |
| --- | --- | --- |
| POST | `/assets` | register a repository |
| GET | `/assets` | list (`search`, `provider`, `monitoring`, `sort_by`, `sort_order`) |
| GET | `/assets/{id}` | detail |
| PUT | `/assets/{id}` | update (rename, branch, monitoring, interval, token) |
| DELETE | `/assets/{id}` | delete asset and all derived data |
| POST | `/assets/{id}/scan` | trigger a manual scan (202) |
| GET | `/assets/{id}/scans` | scan history |
| GET | `/assets/{id}/sboms` | SBOM history |

```bash
curl -X POST http://localhost:8000/api/v1/assets \
  -H 'Content-Type: application/json' \
  -d '{
        "name": "payments-api",
        "repo_url": "https://github.com/acme/payments-api",
        "default_branch": "main",
        "description": "Payments service",
        "access_token": "ghp_xxx",
        "monitoring_enabled": true,
        "scan_interval_minutes": 240
      }'
```

Response `201` includes `has_credential` and `credential_hint` (masked). The
token itself is never returned. Only `https://` URLs on `ANS_ALLOWED_GIT_HOSTS`
are accepted; credentials in the URL, `ssh://`, `file://` and local paths are
rejected with `422`.

Triggering a scan returns `202 {"scan_id": ..., "status": "PENDING"}`, or `409`
if a scan is already pending/running for that asset.

## Scans

| Method | Path | Description |
| --- | --- | --- |
| GET | `/scans` | list (`asset_id`, `status`, `trigger`) |
| GET | `/scans/{id}` | detail with `executions[]` |
| POST | `/scans/{id}/cancel` | cancel a PENDING/RUNNING scan |

`executions[]` exposes scanner status, version, exit code, duration, result
count, stderr excerpt and argv — never credentials (the clone token is passed
via header and never stored in argv).

## Findings

| Method | Path | Description |
| --- | --- | --- |
| GET | `/findings` | list/search/filter/sort |
| GET | `/findings/{id}` | detail + `history[]` |
| PATCH | `/findings/{id}/status` | manual triage transition |

Filters: `search` (title, rule, CVE, package, file), `severity` (multi),
`scanner` (multi), `status` (multi), `asset_id`, `scan_id`, `cve_id`.
Sorting: `sort_by` ∈ {`severity`, `last_detected_at`, `first_detected_at`,
`cvss_score`, `title`, `status`}, `sort_order` ∈ {`asc`, `desc`}.

```bash
curl "http://localhost:8000/api/v1/findings?severity=CRITICAL&status=OPEN&sort_by=cvss_score&sort_order=desc"
curl -X PATCH http://localhost:8000/api/v1/findings/$ID/status \
  -H 'Content-Type: application/json' \
  -d '{"status": "CONFIRMED", "note": "validated by appsec"}'
```

Allowed transitions:

| From | To |
| --- | --- |
| OPEN | CONFIRMED, FALSE_POSITIVE, ACCEPTED_RISK, RESOLVED |
| CONFIRMED | OPEN, FALSE_POSITIVE, ACCEPTED_RISK, RESOLVED |
| FALSE_POSITIVE | OPEN, CONFIRMED |
| ACCEPTED_RISK | OPEN, CONFIRMED, RESOLVED |
| RESOLVED | OPEN, CONFIRMED, FALSE_POSITIVE |

An illegal transition returns `409` with the allowed set. `RESOLVED` sets
`resolved_at`; moving out of `RESOLVED` clears it.

## SBOM

| Method | Path | Description |
| --- | --- | --- |
| GET | `/sboms` | list (`asset_id`) |
| GET | `/sboms/{id}` | metadata incl. provenance (commit, fingerprints, origin, lineage) |
| GET | `/sboms/{id}/packages` | package inventory (`search`, `ecosystem`, pagination) |
| GET | `/sboms/{id}/download` | download the document (`application/json`) |
| GET | `/sboms/{id}/diff` | component diff vs `against` (defaults to the recorded predecessor) |

Documents are served from object storage; the database holds metadata only.

`GET /sboms/{id}/diff` parameters: `against` (snapshot id, must belong to the
same asset — `422` otherwise), `change` ∈ {`ADDED`, `REMOVED`,
`VERSION_CHANGED`, `UNCHANGED`} (default: all changes, unchanged components
excluded), plus pagination. Response:

```json
{
  "previous_sbom_id": "…",
  "current_sbom_id": "…",
  "added": 2, "removed": 1, "version_changed": 3, "unchanged": 740,
  "changed": 6, "total_previous": 744, "total_current": 745,
  "items": [{"change": "VERSION_CHANGED", "identity": "pkg:pypi/requests",
             "identity_basis": "purl", "name": "requests",
             "version_before": "2.31.0", "version_after": "2.32.0",
             "is_direct_before": true, "is_direct_after": true}],
  "total": 6, "page": 1, "page_size": 50, "pages": 1
}
```

Identity is the PURL without its version (then `ecosystem:name`, then `name`), so
a version bump is a change rather than an add + remove, and two ecosystems that
ship the same package name stay separate.

## SBOM lifecycle and continuous monitoring

| Method | Path | Description |
| --- | --- | --- |
| GET | `/assets/{id}/sbom/status` | snapshot overview, freshness, monitoring state, next runs |
| POST | `/assets/{id}/sbom/check` | enqueue a dependency change check (202) |
| POST | `/assets/{id}/sbom/generate` | enqueue an SBOM-only generation (202) |
| POST | `/assets/{id}/sbom/reassess` | enqueue a vulnerability reassessment (202, optional `sbom_id`) |
| GET | `/assets/{id}/sbom/monitoring-runs` | run history (`kind`, `status`, pagination) |
| GET | `/sbom/monitoring/summary` | period counters + estimated scans avoided (`days`, default 30) |

Action endpoints return `202` and are idempotent: they never run work in the
request, and a duplicate request while an equivalent job is queued returns
`{"deduplicated": true, "job_id": "<existing>"}`.

`GET /assets/{id}/sbom/status` (abridged):

```json
{
  "monitoring_status": "DEGRADED",
  "freshness": "STALE",
  "freshness_detail": "dependency inputs changed since this snapshot was generated",
  "latest_snapshot": {"id": "…", "commit_sha": "…", "dependency_fingerprint": "…",
                      "creation_reason": "FULL_SCAN", "package_count": 773,
                      "direct_package_count": null, "generated_at": "…"},
  "vulnerable_components": 4,
  "pending": {"dependency_check": false, "sbom_generation": true,
              "reassessment": false, "dependency_change_pending": true},
  "last_dependency_check": {"status": "SUCCEEDED", "outcome": "DEPENDENCY_CHANGED", "…": "…"},
  "last_reassessment": {"status": "SUCCEEDED", "components_evaluated": 773, "…": "…"},
  "next_dependency_check": "…", "next_reassessment": "…",
  "failed_evaluations_7d": 0,
  "new_findings_since_last_evaluation": 3,
  "new_kev_since_last_evaluation": 1
}
```

`freshness` ∈ {`MISSING`, `CURRENT`, `STALE`, `PENDING`, `FAILED`, `UNKNOWN`}.
`UNKNOWN` means the platform could not verify composition (no check since the
snapshot, or the provider failed) — it is never reported as current.

## Webhooks

| Method | Path | Authentication |
| --- | --- | --- |
| POST | `/api/v1/webhooks/github` | `X-Hub-Signature-256` HMAC-SHA256 over the raw body |
| POST | `/api/v1/webhooks/gitlab` | `X-Gitlab-Token` shared secret |
| GET | `/api/v1/webhooks/health` | none (liveness only) |

Webhook routes are mounted **outside** the API-key router because a provider
cannot send `X-API-Key`. They verify the provider signature against
`ANS_WEBHOOK_SECRET` (503 `webhook_disabled` when unset), ignore non-push
events, ignore pushes to branches other than the asset's default branch, and
enqueue only a lightweight dependency check. Deliveries are deduplicated by
`(provider, delivery_id)`; a replay returns `202 {"status": "DUPLICATE"}` and
enqueues nothing.

```json
{"status": "ENQUEUED", "provider": "github", "delivery_id": "…",
 "reason": "2 dependency input(s) changed", "asset_id": "…", "job_id": "…"}
```

## Vulnerabilities (intelligence)

| Method | Path | Description |
| --- | --- | --- |
| GET | `/vulnerabilities` | list (`search`, `severity`, `source`, `kev_only`, pagination) |
| GET | `/vulnerabilities/{id}` | detail incl. references and affected packages |
| GET | `/vulnerabilities/stats` | totals, per-source/per-severity, last sync |
| POST | `/vulnerabilities/sync/{osv\|nvd\|cisa_kev}` | enqueue a sync (202), `409` if already queued |
| GET | `/vulnerabilities/sync/history` | sync history (`source`, pagination) |

## Dashboard

| Method | Path | Description |
| --- | --- | --- |
| GET | `/dashboard/summary` | assets, findings (severity/scanner/status), scan activity, failing repos, intelligence counters |

## Operations

| Method | Path | Description |
| --- | --- | --- |
| GET | `/system/info` | version, environment, auth state, enabled scanners |
| GET | `/system/scanners` | availability + version probe per tool |
| GET | `/system/dependencies` | database/storage status |
| GET | `/jobs` | job queue history (`status`, `kind`) |
| GET | `/schedules` | configured periodic tasks |
| PATCH | `/schedules/{id}` | enable/disable, change interval |

## AI intelligence

All AI endpoints require the same API key as the rest of the platform. When AI is
disabled or unconfigured, model-backed mutations return `503 ai_unavailable`; the
deterministic endpoints keep working.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/ai/health` | provider, model, configured flag, capabilities, today's spend/tokens |
| GET | `/ai/overview` | dashboard aggregate: highest-risk repositories/findings, review backlog, pending proposals |
| GET | `/ai/executions` | paged execution ledger (`kind`, `status`, `finding_id` filters) |
| GET | `/ai/prompts` | registered prompt ids, versions and hashes |
| GET | `/ai/policies` | versioned policy documents (`kind` filter) |
| POST | `/ai/assistant/ask` | grounded answer over read-only tools (`question`, optional `conversation_id`) |
| GET | `/ai/assistant/conversations/{id}` | transcript including tool calls and rows |
| GET/PUT | `/ai/assets/{asset_id}/security-profile` | business context (criticality, exposure, environment, owner) |
| GET | `/findings/{id}/security-context` | latest context snapshot |
| POST | `/findings/{id}/security-context` | build and persist a context snapshot (no model call) |
| POST | `/findings/{id}/risk-assessment?use_ai=true` | assess risk; `use_ai=false` produces a deterministic-only assessment |
| GET | `/findings/{id}/risk-assessments` | append-only assessment history |
| POST | `/findings/{id}/investigation` | run the investigation workflow (LangGraph) |
| GET | `/findings/{id}/investigations` | investigation history with evidence |
| POST | `/findings/{id}/remediation` | propose remediation (patch proposals only) |
| GET | `/findings/{id}/remediations` | proposals for a finding |
| GET | `/findings/{id}/verifications` | verification history |
| GET | `/remediations` | remediation queue (`status`, `asset_id` filters) |
| GET | `/remediations/{id}` | proposal + verification history |
| POST | `/remediations/{id}/approve` | human approval (records a decision) |
| POST | `/remediations/{id}/reject` | rejection, requires a reason |
| POST | `/remediations/{id}/verify` | move to `VALIDATING` and start a verification scan |
| GET | `/remediations/{id}/verifications` | verifications for a proposal |
| POST | `/verifications/{id}/explain` | attach an AI explanation (status is never changed) |

`POST /findings/{id}/risk-assessment` response (abridged):

```json
{
  "risk_level": "HIGH",
  "cvss_score": 9.8,
  "deterministic_score": 77,
  "ai_risk_score": 80,
  "final_score": 78,
  "confidence": 0.71,
  "deterministic_only": false,
  "requires_human_review": true,
  "signals": [
    {"key": "kev", "value": true, "weight": 0.18, "known": true, "contribution": 0.18},
    {"key": "exposure", "value": null, "weight": 0.12, "known": false, "contribution": 0.06}
  ],
  "evidence": [{"key": "E1", "kind": "finding", "sha256": "...", "cited": true}],
  "missing_information": [{"code": "business_context_not_configured", "message": "..."}]
}
```

## Status codes

| Code | Meaning |
| --- | --- |
| 200 | OK |
| 201 | created |
| 202 | accepted (async work enqueued) |
| 204 | deleted |
| 401 | missing/invalid API key |
| 404 | unknown id |
| 409 | conflict (duplicate repo, active scan, illegal transition, sync already queued) |
| 422 | validation error (URL, payload, filter values) |
| 500 | unexpected server error (details are logged, never returned) |

## Security operations API (2026-11)

All routes below (except ingest and webhooks) require the standard API key when
`ANS_AUTH_ENABLED=true`, and honour per-key asset scope.

### Ingestion (sensor token)

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/ingest/falco` | Falco HTTP output; single object or array; `X-ANS-Ingest-Token`; 503 when unset, 401 when wrong |
| POST | `/ingest/events` | `{"events": [...]}` generic schema; same token |
| GET | `/ingest/health` | `{configured, max_batch}` — no secrets |

### Security events

| Method | Path | Description |
| --- | --- | --- |
| GET | `/events` | filters: `category[]`, `source[]`, `severity[]`, `status[]`, `asset_id`, `incident_id`, `search`, `since`, `sort_by`, `sort_order` |
| GET | `/events/summary` | 24h (configurable) totals, by category/severity, hourly series |
| GET | `/events/{id}` | detail including bounded `raw`, normalized fields, indicators, enrichment |
| GET | `/events/{id}/notes` | analyst notes |
| POST | `/events/{id}/notes` | add a note |
| POST | `/events/{id}/acknowledge` | OPEN → ACKNOWLEDGED |
| POST | `/events/{id}/close` | close with optional `?reason=` |
| GET | `/events/rules` | detection rules (built-in + custom) |
| POST | `/events/rules` | create a custom rule (conditions validated) |
| PATCH | `/events/rules/{id}` | enable/disable, severity, threshold; conditions only for CUSTOM |

### Incidents

| Method | Path | Description |
| --- | --- | --- |
| GET | `/incidents` | `status[]`, `severity[]`, `priority[]`, `asset_id`, `category`, `search`, `active_only` |
| GET | `/incidents/summary` | active count, by status/severity, top open |
| GET | `/incidents/{id}` | incident, asset, events, linked findings, full timeline |
| PATCH | `/incidents/{id}` | `{status, note?}` — transition matrix enforced |
| POST | `/incidents/{id}/assign` | `{assignee}` |
| POST | `/incidents/{id}/notes` | add a timeline note |
| POST | `/incidents/{id}/correlate` | attach related events (same asset, ±24h) and same-CVE findings |
| POST | `/incidents/{id}/investigate` | AI cross-domain investigation (append-only; cannot change the incident) |
| GET | `/incidents/{id}/investigations` | investigation history |

### Infrastructure

| Method | Path | Description |
| --- | --- | --- |
| POST | `/infrastructure/scans` | `{target_kind, scanner, asset_id? , target_ref?}` → PENDING + job |
| GET | `/infrastructure/scans` | list (`asset_id`, `status[]`, `scanner`, `target_kind`) |
| GET | `/infrastructure/scans/{id}` | detail with command metadata and error |
| POST | `/infrastructure/scans/{id}/retry` | new assessment with the same target |
| GET | `/infrastructure/summary` | counts, open findings by severity, scanner availability |
| GET | `/infrastructure/scanners` | availability probe per adapter |
| POST | `/infrastructure/assets` | register a `CONTAINER_IMAGE`/`HOST`/cloud asset |
| GET | `/infrastructure/assets` | list non-repository assets (`kind`) |

### Threat intelligence

| Method | Path | Description |
| --- | --- | --- |
| GET | `/threat-intel/indicators` | filter by `indicator_type`, `source`, `value`, `active` |
| POST | `/threat-intel/indicators` | batch `{source, indicators:[...]}` (≤1000); per-item errors reported, never silently dropped |
| POST | `/threat-intel/indicators/{id}/deactivate` | stop matching an indicator |
| GET | `/threat-intel/summary` | active counts by type/source, last ingest |

### Monitoring and audit

| Method | Path | Description |
| --- | --- | --- |
| GET | `/monitoring/health` | per-control evidence status (`HEALTHY`/`DEGRADED`/`UNKNOWN`/`DISABLED`) |
| GET | `/monitoring/overview` | assets by kind, findings by severity, incidents, 24h events, overall health |
| GET | `/audit` | append-only audit log (`actor`, `action`, `resource_type`, `resource_id`, `search`) |

Status codes follow the existing envelope. New capability-specific responses:
ingestion `503 service_unavailable` when the sensor token is unset, `401` on a
wrong token, `422` on an oversized/invalid batch, `409` when an equivalent
infrastructure assessment is already active, `422` for a non-allowlisted image
registry or an invalid rule condition.
