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
| GET | `/sboms/{id}` | metadata |
| GET | `/sboms/{id}/packages` | package inventory (`search`, `ecosystem`, pagination) |
| GET | `/sboms/{id}/download` | download the document (`application/json`) |

Documents are served from object storage; the database holds metadata only.

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
