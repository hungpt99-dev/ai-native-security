# Architecture

## Goals

1. Collect reliable security data from real tools (no simulated findings).
2. Keep scanners isolated from the API request path and from each other.
3. Normalize heterogeneous scanner output into one finding model that supports
   deduplication, history and future automation.
4. Stay small: one application, one database, one worker binary, one scheduler.

## Process model

| Process | Entry point | Responsibility |
| --- | --- | --- |
| API | `uvicorn app.main:app` | HTTP, validation, persistence, enqueueing |
| Worker | `python -m app.workers.worker` | checkout, scanners, ingestion, correlation |
| Scheduler | `python -m app.scheduler.scheduler` | turns due schedules into jobs |

They share PostgreSQL and nothing else. Each can be scaled independently; the
job queue uses `SELECT ... FOR UPDATE SKIP LOCKED`, so N workers are safe.

### Why a PostgreSQL queue

Phase 1 must not require Redis. `jobs` rows carry status, attempts, backoff,
`run_after`, worker lock and heartbeat. Claims are atomic and never block other
workers. `JobQueue` behaviour is contained in `app/workers/queue.py`; replacing
it with Celery/Redis later means reimplementing `enqueue/claim/heartbeat/
mark_succeeded/mark_failed` — business modules never touch the queue table.

Crash recovery: a worker records `heartbeat_at` as it progresses. Jobs whose
heartbeat is older than `ANS_JOB_STALE_AFTER_SECONDS` are requeued (or failed
after `max_attempts`) at worker startup and periodically.

## Module boundaries

```
app/modules/
├── assets/          # repository inventory + encrypted credentials
├── scans/           # scan lifecycle rows and state machine
├── scanners/        # adapters + hardened subprocess layer (no DB access)
├── sbom/            # SBOM persistence, package inventory, downloads
├── vulnerabilities/ # OSV/NVD/KEV clients, sync, CVSS, correlation
└── findings/        # normalization ingestion, dedup, history, queries
```

Rules that keep the boundaries honest:

* API handlers only validate, call a service and serialize. No SQL in routes
  beyond a single `db.get` for a 404 check.
* Services own transactions and business rules; repositories own queries.
* Scanner adapters return plain dataclasses. They know nothing about SQLAlchemy,
  FastAPI or the database schema, which is what makes them unit-testable from
  captured JSON fixtures.
* The worker orchestrates; it does not re-implement module logic.

## Scan pipeline

`app/workers/pipeline.py` executes one scan:

1. **Guard** — abort if the scan is not PENDING/RUNNING (canceled).
2. **Workspace** — fresh directory under `ANS_WORKSPACE_ROOT`.
3. **Checkout** — `git clone --depth 1 --single-branch --no-recurse-submodules`
   with the branch validated, token passed as an HTTP header (never stored in
   `.git/config`), unsafe symlinks removed, commit SHA recorded.
4. **SBOM** — Syft (CycloneDX by default); document stored via the storage
   abstraction, package rows written to PostgreSQL.
5. **Scanners** — for each enabled scanner: create `scanner_executions` row,
   run, persist exit code, duration, output excerpts, version and result count.
6. **Normalization** — every finding gets a stable fingerprint
   (`asset|scanner|rule|location-or-package`) and is upserted into `findings`.
7. **Correlation** — SBOM packages are queried against OSV at their exact
   installed version; matches become `osv` findings; stored CVSS/KEV data
   enriches trivy/OSV findings by CVE.
8. **Resolution** — only when no scanner failed, and only for scanners that ran
   successfully, findings not seen in this scan become RESOLVED with history.
9. **Summary** — severity counts, new/resolved counts, duration, asset status.
10. **Cleanup** — workspace and scanner reports deleted.

A single status flag is not enough for "did this work?": the pipeline treats any
scanner `FAILED`/`TIMED_OUT` as scan `FAILED` (findings are still stored), which
suppresses auto-resolution because the evidence is incomplete.

## Finding model

* Identity = `(asset_id, fingerprint)`, enforced by a unique constraint.
  Scanner-generated ids are excluded because they change between runs.
* A finding is *per asset*, not per scan: `first_scan_id`/`last_scan_id` track
  provenance and "still detected" semantics.
* Every transition appends a `finding_history` row: DETECTED, REOPENED,
  STATUS_CHANGED, AUTO_RESOLVED.
* Version-aware fingerprints mean a dependency upgrade produces a new finding
  (new identity) and resolves the old one — accurate for triage.

## Vulnerability intelligence

| Source | Client | Sync strategy |
| --- | --- | --- |
| OSV | `POST /v1/querybatch`, `GET /v1/vulns/{id}` | per inventoried package/version; details hydrated on demand |
| NVD | `GET /rest/json/cves/2.0` with `lastModStartDate` | incremental window (≤120 days), page commit, rate-limit delay |
| CISA KEV | full catalog JSON (~1.7k entries) | full replace + flag existing OSV/NVD rows |

Records are keyed by `(source, source_id)` — not by CVE — because OSV entries
often have no CVE and NVD entries are CVE-only. `cve_id` is a nullable
correlation column. CVSS is computed from the vector when a source only
publishes one (OSV), and stays `NULL` when unavailable; severity is never
invented.

## Scheduling

`schedules` rows describe periodic work (`asset-scan:<uuid>`, `sync:osv`,
`sync:nvd`, `sync:kev`). The scheduler:

* acquires a PostgreSQL advisory lock (single scheduler instance),
* refreshes asset scan schedules every 5 minutes from `assets.monitoring_enabled`
  and `scan_interval_minutes`,
* claims due rows `FOR UPDATE SKIP LOCKED` and enqueues jobs in the same
  transaction that advances `next_run_at`, which makes duplicate enqueues
  impossible,
* records `last_status`/`last_error` for visibility, and skips scans that are
  already active.

## Frontend

React 18 + TypeScript + Vite + Tailwind v4 + TanStack Query, shadcn-style
primitives built on Radix (`Dialog`, `Select`). Server state is entirely
TanStack Query; there is no mock data path in production flows. Pages:
dashboard, repositories, repository detail, scans, scan detail, findings,
SBOM list/detail, intelligence, operations.

## Decisions worth re-reading

* **Sync SQLAlchemy + psycopg3.** FastAPI runs sync handlers in a thread pool;
  this keeps the code simple and typed, and avoids async/sync mixing in the
  worker. Revisit only if the API becomes connection-bound.
* **No ORM in scanner adapters.** They must be runnable from a fixture file in a
  unit test and from a future standalone CLI.
* **PostgreSQL-only types** (JSONB, partial unique index) are used where they buy
  real correctness: JSONB for scanner metadata, a partial unique index to
  guarantee one active scan per repository.
* **Storage abstraction** (`StorageBackend`) for SBOM documents: local files now,
  S3 later, with keys validated against the root to block traversal.
* **No Celery yet.** A single `jobs` table is enough for one worker; the
  interface is deliberately narrow so it can be swapped.
