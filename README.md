# AI-Native Security Platform

Self-hosted security platform that continuously scans source repositories,
generates SBOMs, correlates vulnerabilities with public intelligence feeds,
investigates them **in application context** with an LLM, proposes remediation and
then proves with a fresh scan whether the fix actually worked.

The design rule is: **AI proposes, evidence disposes.** The model reasons over
structured evidence and produces structured, cited output; scanners, version
comparisons, policy gates and verification results stay deterministic and remain
the only authority on whether something is fixed.

It is still a **modular monolith**: one FastAPI application, one worker, one
scheduler, PostgreSQL and a React dashboard. The AI layer is a module inside it —
no microservices, no Kafka, no Kubernetes, no vector database.

```
 ┌──────────┐   REST    ┌──────────────┐   SQL   ┌────────────┐
 │ React UI │ ────────► │ FastAPI (API)│ ──────► │ PostgreSQL │
 └──────────┘           └──────┬───────┘         └─────┬──────┘
                               │ enqueue job           │ claim job
                               ▼                       ▼
                        ┌──────────────┐        ┌──────────────┐
                        │ jobs (PG)    │◄──────►│ Worker       │
                        └──────────────┘        │ syft/trivy/  │
                               ▲                │ semgrep/     │
                        ┌──────┴───────┐        │ gitleaks     │
                        │ Scheduler    │        └──────────────┘
                        └──────────────┘
```

## What works today

| Capability | Status |
| --- | --- |
| Repository registration (GitHub/GitLab, optional encrypted token) | implemented |
| Manual + scheduled scans, cancellation, one active scan per repo | implemented |
| Isolated worker with `git` checkout, hardened subprocess execution | implemented |
| Syft SBOM generation (CycloneDX, SPDX supported) + package inventory | implemented |
| Trivy (dependencies/OS packages), Semgrep (SAST), Gitleaks (secrets) | implemented |
| Finding normalization, stable deduplication, history, auto-resolution | implemented |
| OSV, NVD, CISA KEV clients + scheduled incremental sync + KEV enrichment | implemented |
| Dashboard, repository, scan, finding, SBOM and operations pages | implemented |
| Automated tests (unit, integration, security) | implemented |
| API-key authentication (optional), credential encryption, secret redaction | implemented |
| Security context builder (repository, finding, dependency, vulnerability, business, history) | implemented |
| AI risk assessment: deterministic signals + policy blend + cited AI judgement | implemented |
| AI investigation workflow (LangGraph) with evidence citations and bounded statuses | implemented |
| AI remediation proposals (patch proposals only, version-checked against intel) | implemented |
| Approval workflow + deterministic verification (re-scan diff, new-risk detection) | implemented |
| Security assistant with read-only, asset-scoped tools | implemented |
| Decision history, feedback capture, versioned security policies | implemented |
| EPSS exploitation probability ingest | implemented |

Not part of this phase: pull-request creation, deployment verification, runtime
detection, SIEM, attack-path analysis (symbol-level reachability), microservices,
Kubernetes, Kafka, a vector database.


## Requirements

* Docker + Docker Compose v2 (recommended), or
* Python 3.12+, Node 22+, PostgreSQL 16 for local development

## Quick start (Docker Compose)

```bash
cp .env.example .env
# Set a strong secret: it derives the repository-credential encryption key.
sed -i "s/^ANS_SECRET_KEY=.*/ANS_SECRET_KEY=$(openssl rand -hex 32)/" .env

docker compose up --build -d
docker compose ps
```

* Dashboard: <http://localhost:8080>
* API docs (OpenAPI): <http://localhost:8000/docs>
* Health: <http://localhost:8000/healthz>, readiness: `/readyz`

Register a repository and start a scan:

```bash
curl -s -X POST http://localhost:8000/api/v1/assets \
  -H 'Content-Type: application/json' \
  -d '{"name":"nodegoat","repo_url":"https://github.com/OWASP/NodeGoat","default_branch":"master"}' \
  | tee /tmp/asset.json

ASSET_ID=$(python3 -c "import json;print(json.load(open('/tmp/asset.json'))['id'])")
curl -s -X POST "http://localhost:8000/api/v1/assets/$ASSET_ID/scan"
curl -s "http://localhost:8000/api/v1/scans?asset_id=$ASSET_ID"
```

The `migrate` service runs `alembic upgrade head` before the API, worker and
scheduler start, so the first boot needs no manual steps.

## Local development

```bash
# 1. PostgreSQL
docker run -d --name ans-postgres -p 5432:5432 \
  -e POSTGRES_USER=security -e POSTGRES_PASSWORD=security -e POSTGRES_DB=security \
  postgres:16-alpine

# 2. Backend
cd backend
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
export ANS_DATABASE_URL=postgresql+psycopg://security:security@localhost:5432/security
export ANS_SECRET_KEY=dev-secret
alembic upgrade head
uvicorn app.main:app --reload --port 8000

# 3. Worker + scheduler (separate terminals)
python -m app.workers.worker
python -m app.scheduler.scheduler

# 4. Frontend
cd ../frontend
npm install
npm run dev            # http://localhost:5173, proxies /api to :8000
```

Scanner binaries must be installed for real scans:
`trivy`, `semgrep`, `gitleaks`, `syft` (the worker Docker image already
contains pinned versions). Override their locations with `ANS_TRIVY_BINARY`,
`ANS_SEMGREP_BINARY`, `ANS_GITLEAKS_BINARY`, `ANS_SYFT_BINARY`.

### Database migrations

```bash
cd backend
alembic upgrade head          # apply
alembic revision --autogenerate -m "describe change"
alembic downgrade -1          # roll back one revision
```

## Tests

```bash
cd backend
# Integration tests use a real PostgreSQL database named security_test
# (created automatically; set ANS_TEST_DATABASE_URL to override).
pytest -q
ruff check app tests
```

The suite covers scanner output parsing, finding normalization/deduplication,
status and scan-state transitions, asset/scan/finding/SBOM APIs with controlled
fixtures, vulnerability sync with mocked feeds, and security checks (command
injection, URL validation, credential masking, path traversal, unauthorized
access). No external network access is required.

## Configuration

Every setting is an environment variable with the `ANS_` prefix; see
`.env.example` for the full list. The most important ones:

| Variable | Purpose |
| --- | --- |
| `ANS_DATABASE_URL` | PostgreSQL SQLAlchemy URL |
| `ANS_SECRET_KEY` / `ANS_CREDENTIAL_KEY` | derives the token encryption key |
| `ANS_AUTH_ENABLED`, `ANS_API_KEYS` | API-key auth (comma separated) |
| `ANS_ALLOWED_GIT_HOSTS` | clone allow-list (default `github.com,gitlab.com`) |
| `ANS_SCANNER_TIMEOUT_SECONDS`, `ANS_SCANNER_MAX_MEMORY_MB` | scanner limits |
| `ANS_SEMGREP_CONFIG`, `ANS_SEMGREP_JOBS` | Semgrep ruleset and parallelism |
| `ANS_NVD_API_KEY`, `ANS_NVD_INITIAL_LOOKBACK_DAYS` | NVD rate limit (5 → 50 req/30s) and first-sync window |
| `ANS_*_SYNC_INTERVAL_MINUTES` | vulnerability + scan cadence |
| `ANS_STORAGE_ROOT`, `ANS_STORAGE_BACKEND` | SBOM artifact storage |

## Project layout

```
ai-native-security/
├── backend/
│   ├── app/
│   │   ├── api/v1/            # HTTP layer (thin handlers, enforces auth)
│   │   ├── core/              # config, logging, errors, security, storage, validation
│   │   ├── database/          # engine/session, declarative base, model registry
│   │   ├── modules/           # assets, scans, scanners, sbom, vulnerabilities, findings
│   │   ├── scheduler/         # periodic job enqueueing
│   │   ├── workers/           # queue, checkout, pipeline, worker loop
│   │   └── main.py
│   ├── alembic/               # migrations
│   └── tests/
├── frontend/                  # React + TypeScript + Vite + Tailwind + TanStack Query
├── docker/                    # Dockerfiles (api/worker/scheduler, frontend), nginx
├── docs/                      # architecture, ERD, API, security notes
├── docker-compose.yml
└── .env.example
```

## Documentation

* [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — modules, scan pipeline, decisions
* [`docs/ERD.md`](docs/ERD.md) — data model and relationships
* [`docs/API.md`](docs/API.md) — endpoint reference and examples
* [`docs/SECURITY.md`](docs/SECURITY.md) — threat model for untrusted repos/scanners
* [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — running, backups, troubleshooting

## Operational notes

* The worker claims jobs with `FOR UPDATE SKIP LOCKED`, so
  `docker compose up --scale worker=2` is safe.
* Jobs abandoned by a crashed worker are reaped after
  `ANS_JOB_STALE_AFTER_SECONDS` and retried up to `ANS_JOB_MAX_ATTEMPTS`.
* Findings are only auto-resolved when a scan completes *successfully* and only
  for scanners that produced a successful run.
* Gitleaks runs with `--redact`; secret values are never persisted or returned.
* The first Trivy scan downloads its vulnerability database (~1 GB in the
  `trivy-cache` volume); plan for that on first run.

## License

Proprietary — internal use.
