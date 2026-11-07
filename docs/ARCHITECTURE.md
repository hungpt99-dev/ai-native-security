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
├── assets/               # repository inventory + encrypted credentials
├── scans/                # scan lifecycle rows and state machine
├── scanners/             # adapters + hardened subprocess layer (no DB access)
├── sbom/                 # SBOM persistence, inventory, dependency detection, diff, lifecycle
├── git_provider/         # GitHub/GitLab metadata client, webhook verification + delivery log
├── vulnerabilities/      # OSV/NVD/KEV/EPSS clients, sync, CVSS, correlation, reassessment
├── findings/             # normalization ingestion, dedup, history, queries
├── security_intelligence/# context builder, dependency graph, version maths, snippets
├── ai/                   # providers, prompts, agents, workflows, ledger, assistant tools
├── risk_analysis/        # deterministic signals + AI risk assessment
├── security_policies/    # versioned policy documents
├── remediation/          # proposals + approval lifecycle
├── verification/         # deterministic post-fix verification
└── knowledge_base/       # decisions, feedback, assistant transcripts
```

The AI layer is documented separately in [`AI_ARCHITECTURE.md`](AI_ARCHITECTURE.md).
Boundary rules: business modules never import `ai.providers`; only `ai/**` may
construct a provider; `security_intelligence` and `verification` never import the
AI layer at all, so they stay runnable with AI disabled.

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
9. **Repository facts** — languages, frameworks and manifest list derived from the
   SBOM plus a bounded workspace walk (`asset_repository_metadata`).
10. **Code evidence** — for findings without scanner-provided lines, capture a
    bounded, redacted snippet around the reported location.
11. **Summary** — severity counts, new/resolved counts, duration, asset status.
12. **Verification** — if the asset has approved remediations in flight, evaluate
    them against this scan's evidence (deterministic statuses only).
13. **AI queueing** — when AI is enabled, queue contextual risk analysis for the
    highest-severity new findings (bounded by `ANS_AI_AUTO_ANALYZE_MAX_FINDINGS`).
14. **Cleanup** — workspace and scanner reports deleted.

Steps 12 and 13 are best-effort: a failure there is logged and never rewrites the
scan's own outcome.

A single status flag is not enough for "did this work?": the pipeline treats any
scanner `FAILED`/`TIMED_OUT` as scan `FAILED` (findings are still stored), which
suppresses auto-resolution because the evidence is incomplete.

## Three distinct operations

The platform separates three operations that are routinely conflated. They have
different costs, different failure semantics and different evidence.

| | Full security scan | SBOM update | Vulnerability reassessment |
| --- | --- | --- | --- |
| Job kind | `SCAN` | `SBOM_CHANGE_CHECK` → `SBOM_GENERATE` | `SBOM_VULNERABILITY_REASSESSMENT` |
| Clones the repository | yes | yes (generation only; the check never clones) | **no** |
| Runs Syft | yes | yes | **no** |
| Runs Trivy/Semgrep/Gitleaks | yes | **no** | **no** |
| Writes a finding | yes | no | yes (from stored intel) |
| Writes an SBOM snapshot | yes (`FULL_SCAN`) | yes (immutable, lineage-linked) | no |
| Trigger | schedule/manual | webhook, schedule, dependency change, manual | daily schedule, intel sync, manual |

### B. SBOM update

`modules/sbom/lifecycle.py` decides whether the stored snapshot still describes
the repository. It never runs the security scanner pipeline.

1. Resolve the branch head — provider REST API, or `git ls-remote` (refs only).
   A failed lookup is `UNKNOWN`, never "up to date".
2. `head == snapshot.commit_sha` → `UNCHANGED`; nothing else happens.
   A snapshot with no recorded commit is `UNKNOWN` (never "current") and a
   `BASELINE` generation is queued to re-establish a comparable state.
3. Otherwise compare commits and classify the changed paths
   (`modules/sbom/dependencies.py`). A commit change alone is **not** a
   dependency change: only manifest / lockfile / build-input paths count.
4. Dependency paths → enqueue `SBOM_GENERATE` (deduplicated by asset + head SHA).
   Business-logic-only paths → record `NO_DEPENDENCY_CHANGE` and stop.
5. Generation checks out, runs Syft, hashes the dependency inputs and the
   resolved inventory, and stores a new snapshot with `previous_snapshot_id`.
6. Old vs new inventories are diffed (`modules/sbom/diff.py`) and a reassessment
   of the new snapshot is queued.

Layers of evidence, in order of preference:

1. manifest/lockfile/build-config fingerprint (`manifest_fingerprint`);
2. changed-path classification from the provider;
3. commit SHA;
4. resolved inventory fingerprint (`dependency_fingerprint`);
5. artifact digest (`artifact_digest`) — only when an SBOM was generated from a
   build artifact; directory scans leave it `NULL` instead of reusing another
   hash.

The four identifiers are deliberately distinct: document checksum (`sha256`),
resolved composition (`dependency_fingerprint`), declared inputs
(`manifest_fingerprint`) and Git state (`commit_sha`). None is derived from
another.

### C. Continuous vulnerability reassessment

`modules/vulnerabilities/reassessment.py` correlates **stored** inventory with
**stored** intelligence:

1. load `sbom_packages` for a snapshot (bounded by
   `ANS_SBOM_MAX_REASSESSMENT_COMPONENTS`);
2. load matching `vulnerability_affected_packages` + `vulnerabilities` in chunked
   queries, plus EPSS and references in batch — no external API call;
3. evaluate each version with `security_intelligence/versions.py`
   (`is_affected`), the same comparator risk analysis and remediation use;
4. upsert findings through `findings.service.record_findings` with
   `scan_id = NULL` and `discovery_source = SBOM_REASSESSMENT`;
5. enrich KEV/EPSS through `vulnerabilities.correlation.enrich_findings`
   (shared with the scan path);
6. resolve findings only on positive evidence.

Identity is unchanged: `(asset_id, fingerprint)` with
`fingerprint = sha256(asset|scanner|rule|package|version)`. A vulnerability found
by both a scan and a reassessment is one finding whose
`metadata.evidence_sources` lists both paths.

Resolution rules:

| Evidence | Outcome |
| --- | --- |
| exact installed version still inventoried, ranges exclude it | resolve (`version_no_longer_affected`) |
| exact version gone, package present at another version, inventory provenance | resolve (`package_version_changed`) |
| package gone from the inventory, inventory provenance | resolve (`package_removed_from_inventory`) |
| intelligence record missing for an active finding | **no** resolution, `needs_review` |
| range data unusable (GIT ranges, unparseable versions) | **no** resolution, run `PARTIAL` |
| inventory truncated by the component ceiling | **no** resolution, run `PARTIAL` |

A failed or partial assessment never resolves anything, and a missing intel
record is explicitly not treated as a fix.

Findings whose only provenance is an inventory snapshot are closed by
reassessment, not by the scan resolver: `resolve_missing_findings` keys on
`last_scan_id`, and a finding no scan ever confirmed keeps that column `NULL` on
purpose. Once a scan re-detects the same finding (same fingerprint) it gains
`last_scan_id` and returns to the normal scan lifecycle.

Risk assessments are **not** recomputed for findings whose evidence did not
change: `risk_assessments` is append-only, and rewriting it on every daily pass
would create history without new evidence. What reassessment does update is the
deterministic input (severity, CVSS, KEV, EPSS). Findings created by a
reassessment go through the existing AI policy gate (`workers/automation.py`),
which is the only place that decides whether a model call is justified.

## Dependency change detection

`modules/sbom/dependencies.py` owns the canonical registry of dependency inputs
(`MANIFEST`, `LOCKFILE`, `BUILD_CONFIG`) for Maven/Gradle, npm/yarn/pnpm,
Python (requirements/pyproject/poetry/uv/Pipenv/conda), Go, Rust, .NET, Ruby,
PHP, Swift, Dart, Elixir and Docker/compose. It is basename-based so monorepos
and per-service manifests are matched at any depth. `security_intelligence`
reuses `is_manifest_path` from it instead of keeping a second list.

Covered cases: unchanged commit, business-logic-only commit, lockfile change
without manifest change, added/removed/renamed manifests, multiple manifests,
monorepo layouts, build-config changes, branch change (forces a new snapshot,
never reuses another branch's snapshot), provider failure (`UNKNOWN`),
truncated compare payload (treated as *possibly changed* — the conservative
direction).

## Scheduling

`schedules` rows describe periodic work (`asset-scan:<uuid>`,
`asset-sbom-check:<uuid>`, `sync:osv`, `sync:nvd`, `sync:kev`, `sync:epss`,
`sbom:reassess`). The scheduler:

* acquires a PostgreSQL advisory lock (single scheduler instance),
* refreshes per-asset scan **and** SBOM check schedules every 5 minutes from
  `assets.monitoring_enabled`; the two intervals are independent, so composition
  monitoring does not inherit the scan cadence,
* claims due rows `FOR UPDATE SKIP LOCKED` and enqueues jobs in the same
  transaction that advances `next_run_at`,
* enqueues idempotently (`queue.enqueue_once`): an equivalent queued/running job
  is reused and the schedule records `DEDUPLICATED`,
* records `last_status`/`last_error` for visibility, and skips scans that are
  already active.

Daily monitoring never enqueues a `SCAN`: `sbom:reassess` is a
`SBOM_VULNERABILITY_REASSESSMENT` job that only reads the database.

## Concurrency, idempotency, failure handling

* Per-operation PostgreSQL advisory locks (`check`, `generate`, `reassess`) are
  keyed by asset. A second worker skips instead of racing; a crashed worker
  releases its lock with the connection, so no stale row can block an asset.
* Generation is deduplicated twice: the application skips when inventory and
  commit match the latest snapshot, and a partial unique index
  `(asset_id, dependency_fingerprint, commit_sha) WHERE ... creation_reason <> 'FULL_SCAN'`
  rejects a concurrent duplicate. Full scans are exempt because each scan owns
  its artifact.
* Jobs are deduplicated by payload match (`asset_id`, and `head_sha`/`sbom_id`
  where relevant). Retries use exponential backoff; stale heartbeats requeue.
* Every attempt is a committed `sbom_monitoring_runs` row (`RUNNING` first), so a
  crash leaves a visible record instead of a rolled-back transaction. Failed
  generation creates **no** snapshot row: a snapshot that exists always has a
  readable document behind `storage_key`.
* Reassessment is idempotent: same inventory + same intelligence produces no new
  findings and no new history rows.

## Observability

Structured logs (`sbom snapshot generated`, `sbom monitoring run finished`,
`webhook dependency check enqueued`, `job enqueue deduplicated`) carry
asset/run/job identifiers and counts. Every run row records duration, components
evaluated, findings created/updated/resolved, new KEV findings and failure
counts. `GET /sbom/monitoring/summary` aggregates a window and reports estimated
scans/checkouts/scanner executions avoided — an estimate, with its formula
exposed in `estimate_basis`, derived from checks that proved composition
unchanged.

## Webhooks

`git_provider` verifies GitHub (`X-Hub-Signature-256`, HMAC-SHA256 over the raw
body) and GitLab (`X-Gitlab-Token`, constant-time compare) deliveries against
`ANS_WEBHOOK_SECRET`. Routes are mounted outside the API-key router because a
provider cannot send `X-API-Key`. A delivery is stored in
`webhook_deliveries` with `UNIQUE (provider, delivery_id)`; a replay is a no-op.
Only push events to the asset's default branch produce work, and the request
only enqueues — nothing is cloned or scanned inside the HTTP call. When the
webhook secret is unset the endpoints answer `503` instead of trusting input.
Polling (`asset-sbom-check:<uuid>`) remains available as the fallback when
webhooks cannot be configured.

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

## Frontend

React 18 + TypeScript + Vite + Tailwind v4 + TanStack Query, shadcn-style
primitives built on Radix (`Dialog`, `Select`). Server state is entirely
TanStack Query; there is no mock data path in production flows. Pages:
dashboard, repositories, repository detail (with the SBOM & continuous
monitoring panel), scans, scan detail, findings, SBOM list/detail/compare,
intelligence, operations.

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

## Security domains (runtime, infrastructure, incidents)

The platform keeps the modular monolith and adds four modules that share the
existing asset/finding/queue infrastructure instead of forking it:

```
app/modules/
├── events/        # ingestion, normalization, detection rules, anomaly, event API
├── incidents/     # lifecycle, timeline, correlation, deterministic risk
├── infrastructure/# IaC/image assessment adapters + scan service
├── threat_intel/  # IOC storage, ingestion, exact matching
├── audit/         # append-only audit log + request middleware
└── monitoring/    # evidence-based health and unified overview
```

### Unified asset inventory

`assets` now carries `kind` (`REPOSITORY`, `CONTAINER_IMAGE`, `HOST`,
`CLOUD_RESOURCE`, `KUBERNETES_WORKLOAD`, `API_SERVICE`), an `external_ref`
(unique per kind, e.g. `docker://nginx:1.25`, `host://api-01`) and an optional
`parent_asset_id`. Repository assets keep `repo_url`; non-repository assets have
`repo_url = NULL`. One table means one owner, one criticality profile, one
finding stream — container findings and repository findings are triaged the same
way.

### Event pipeline

```
sensor → /ingest → normalize → asset resolve → fingerprint (dedupe)
       → threat-intel match → signature rules → threshold rules
       → deterministic risk → incident create/attach → timeline
```

The pipeline is synchronous inside the API request and bounded at every step
(batch, body, field, scan window). No queue is needed for ingestion: the work is
a handful of indexed writes. See `RUNTIME_SECURITY.md` for the contract.

### Infrastructure assessment

`INFRA_SCAN` is a worker job. The API creates a `PENDING` row and enqueues; the
worker clones (IaC targets only), runs Trivy/Checkov through the hardened
subprocess layer, records findings through `findings.service.record_findings`
(`discovery_source=INFRASTRUCTURE_SCAN`), and stores counts/command/error on the
scan row. Container images are pulled by the scanner; the platform never needs a
Docker socket.

### Incidents and correlation

Incidents are created only by detection rules (or correlation), never by AI.
`correlation_key = rule_slug:asset` plus a reuse window prevents alert storms from
creating incident storms. Risk is deterministic
(`incidents/risk.py`, version `incident-risk/1`). The timeline is append-only and
is the investigation record. AI investigation reads an aggregated, bounded
evidence set and appends a report; it cannot change status, severity, priority or
risk.

### Why no new infrastructure

Events, incidents and audits are PostgreSQL rows with indexed query paths; the
existing `FOR UPDATE SKIP LOCKED` queue already provides retries and recovery.
Kafka/Redis would add operational surface without a measured need at this scale.
Module boundaries (`api.py`, `service.py`, `models.py`, `scanners.py`) keep each
domain extractable later.

### Frontend

New surfaces reuse the existing shell and primitives: `/monitoring`
(health strip, event table, detail dialog, rule toggles), `/incidents` and
`/incidents/:id` (lifecycle, timeline, evidence, AI report), `/infrastructure`
(scanner availability, scans, assets) and a security-operations strip on the
dashboard. All data is real API data; empty and error states are explicit.
