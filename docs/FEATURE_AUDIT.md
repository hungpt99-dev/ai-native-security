# Feature Audit — AI-Native Security Platform

Audited at commit `a38b34a` (main), against the running stack (`docker compose`, PostgreSQL with
real scan data) and the request's capability list. Every row was verified in source, not from the
README.

Status vocabulary: **Working** · **Incomplete** · **Mocked** · **Documented only** · **Missing** ·
**Insecure/unreliable**.

## 1. Audit table

| Feature | Current Status | Evidence | Missing Work | Priority |
| --- | --- | --- | --- | --- |
| Asset inventory (CRUD) | Working | `modules/assets/api.py`, `service.py`; unique `repo_url`; soft monitoring flag | — | — |
| GitHub/GitLab repository registration | Working | `core/enums.py::Provider`; `asset_credentials` with Fernet-encrypted tokens (`core/security.py`) | Token validation against the provider API before saving | P3 |
| Private repository access | Working | `assets/service.resolve_access_token`, `workers/checkout.py` passes the token via HTTP header, never into `.git/config` | — | — |
| Repository metadata (languages, frameworks, manifests) | Missing | `Asset` has only `name/repo_url/provider/default_branch/description` (`modules/assets/models.py`) | Derive from SBOM ecosystems + workspace manifest listing at scan time | **P1** |
| Asset criticality / environment / internet exposure / ownership | Missing | No columns, no profile table anywhere | `asset_security_profiles` + API + UI | **P1** |
| Branch selection per scan | Missing | `scans/service.create_scan` always uses `asset.default_branch`; trigger endpoint has no payload (`api/v1/scans.py`) | Optional `branch` on scan creation with validation | P2 |
| Scan scheduling | Working | `scheduler/scheduler.py`, `Schedule` model, `scan_interval_minutes` | — | — |
| Scanner execution (Trivy/Semgrep/Gitleaks/Syft) | Working | `modules/scanners/*.py` + `scanners/execution.py` (argv-only, rlimits, timeouts); real e2e run produced 190 findings | — | — |
| Scanner version tracking | Working | `ScannerExecution.version`, `result_count`, exit code, stdout/stderr excerpts | — | — |
| Scanner failure semantics | Working | `workers/pipeline.py` marks scan FAILED and skips auto-resolution | — | — |
| SBOM generation and storage | Working | `scanners/syft.py`, `modules/sbom/service.py`, `core/storage.py` | — | — |
| SBOM package inventory | Working | `sbom_packages` (770 rows today) | — | — |
| Direct vs transitive dependency graph | Missing | Syft parser discards CycloneDX `dependencies`; `SbomPackage` has no parent/`is_direct` | Parse edges into `sbom_package_edges`, add `is_direct` — **done after this audit**: parser, storage and analysis exist; the Syft build used here emits no `dependencies` for directory scans, so the platform reports the graph as unavailable instead of guessing | **P1** |
| Package → vulnerability correlation | Working | `vulnerabilities/correlation.py` (exact-version OSV batch, KEV promotion, `Upsert` intel) | Correlation capped at 750 packages / 150 detail fetches — document as a limit | P2 |
| OSV / NVD / CISA KEV sync | Working | `vulnerabilities/{osv,nvd,kev,sync}.py`, `vulnerability_sync_history` (NVD SUCCESS, 40k records) | — | — |
| EPSS exploit probability | Missing | No model, no client | `vulnerability_epss` + incremental daily sync | **P1** |
| Fixed / affected version data | Working (stored) | `vulnerability_affected_packages.fixed_versions/affected_versions/version_ranges` | — | — |
| Deterministic version comparison | Missing | No comparator; OSV is queried by exact version (`osv.py`) | `security_intelligence/versions.py` with per-ecosystem tests | **P1** |
| Finding normalization + dedup | Working | `findings/service.record_scan_findings`, fingerprint `asset|scanner|rule|location-or-package` | — | — |
| Finding lifecycle + history | Working | `FindingHistory`, `ALLOWED_FINDING_TRANSITIONS`, auto-resolve only after a clean scan | — | — |
| Finding evidence (code snippets) | Incomplete | Semgrep stores `metadata.lines` (≤1000 chars, credential-redacted); Gitleaks stores masked secret; workspace deleted after scan (`pipeline.py` finally) | Bounded snippet capture at scan time for non-Semgrep findings | P2 |
| Findings filtering/pagination API | Working | `api/v1/findings.py`, `findings/repository.py` | — | — |
| Dashboard aggregates | Working | `api/v1/dashboard.py` | AI/risk sections | P2 |
| Authentication | Incomplete | `api/deps.py`: static API keys, `ANS_AUTH_ENABLED=false` by default, single `Principal.subject` | Per-asset authorization scope for AI/assistant reads | **P1** |
| Authorization (per asset) | Missing | No ACL anywhere | `Principal.asset_scope` enforced in AI endpoints and assistant tools | **P1** |
| Job queue + retries + heartbeat | Working | `workers/queue.py` (`FOR UPDATE SKIP LOCKED`), `Job`, stale recovery | — | — |
| AI provider abstraction | Missing | No AI code exists (`grep -r openai|langgraph` → 0 hits) | `ai/providers` (OpenAI-compatible HTTP, retries, rate limit, usage/cost) | **P1** |
| AI execution tracking | Missing | — | `ai_executions` ledger + observability | **P1** |
| Prompt versioning | Missing | — | Versioned prompt registry, sha256 of rendered prompt | **P1** |
| Security context builder | Missing | — | Deterministic context assembly + snapshots | **P1** |
| AI risk analyst | Missing | — | Signals + AI output + append-only `risk_assessments` | **P1** |
| AI security analyst / investigation | Missing | — | LangGraph workflow + `security_investigations`/`investigation_evidence` | **P1** |
| AI remediation assistant | Missing | — | Recommendations, patch proposals (never applied) | **P2** |
| Remediation approval workflow | Missing | — | State machine + `security_decisions` | **P2** |
| Verification engine (post-fix rescan diff) | Missing | No diff logic; `create_scan` exists to reuse | `remediation_verifications` + scan diff + policy gate | **P1** |
| Deployment verification | Missing | No deployment integration exists | Out of scope for this environment: verification stops at re-scan evidence; documented explicitly | P3 |
| Knowledge base / decision history | Missing | — | `security_decisions`, FTS retrieval | P2 |
| AI feedback loop | Missing | — | `ai_feedback` + retrieval influence | P2 |
| Natural-language assistant | Missing | — | Typed read-only tools + `assistant_*` tables + UI | P2 |
| Policy engine | Missing | Rules are hardcoded in code (`_promote_severity`, thresholds inline) | Versioned `security_policies` rows + evaluator | **P1** |
| Frontend: existing pages | Working | 10 pages in `frontend/src/pages`, react-query hooks, typed API client | AI surfaces | P2 |
| Frontend: AI overview / risk / remediation / assistant | Missing | — | 4 new surfaces | P2 |
| Tests | Working | 97 tests (unit + integration on real PostgreSQL, transactional rollback) | AI provider, context, guardrails, workflows, verification | **P1** |
| CI/CD | Missing | No `.github/workflows`, no pipeline file | `ci.yml`: ruff + mypy + pytest (Postgres service) + frontend build | **P1** |
| Docs | Working | `docs/{ARCHITECTURE,API,ERD,SECURITY,OPERATIONS}.md` accurate for Phase 1 | AI architecture, ERD, API, security table row 9 ("no LLM in the loop") is now stale | P2 |

## 2. Structural findings

**Duplicates:** none material. `scans/service.py` and `api/v1/scans.py` are a clean service/router
split. `vulnerabilities/http.py` and the new AI provider both need an HTTP client — the AI provider
**must not** reuse `HttpClient` (it is tuned for feed downloads and retries on different semantics);
one shared implementation would be the wrong abstraction.

**Dead code:** `get_scan_with_executions` (`scans/service.py`) just calls `get_scan_or_404` — the
name lies. `_cleanup_reports` imports `shutil` inside the function body. Neither is a defect, both
are noise to clean while touching the file.

**Inconsistent data models:** `Finding.cvss_score` is `Numeric(3,1)` while `Vulnerability.cvss_score`
is the same type but is read back as `Decimal` in one place and `float` in another
(`correlation.py` casts explicitly, `schemas.py` does not) — tolerable, but the AI schemas must
normalise to `float` once and not propagate `Decimal` into JSON.

**Broken integrations:** none found in the scan path (verified e2e). The gap is *missing* inputs,
not broken wiring.

**Security weaknesses found:**

| # | Issue | Location | Severity |
| --- | --- | --- | --- |
| W1 | Authorization is all-or-nothing: one API key sees every asset. Acceptable for a single-tenant local install, unacceptable for the assistant ("apply asset-level authorization") | `api/deps.py` | High (for AI scope) |
| W2 | `ANS_SECRET_KEY` defaults to `change-me-in-production`; credential encryption silently derives from it | `core/config.py:52` | Medium |
| W3 | `ANS_AUTH_ENABLED=false` default: every endpoint is open if deployed as-is | `core/config.py:56` | Medium |
| W4 | Scanner stdout/stderr excerpts persisted verbatim (`stdout_excerpt`) — may contain repository content or CI secrets printed by a tool | `scanners/execution.py`, `pipeline.py` | Low (redaction exists but is not applied here) |
| W5 | `resolve_missing_findings` resolves by absence of detection — correct today, but once AI exists, nothing prevents a future caller from passing a partial scanner list and mass-resolving | `findings/service.py` | Low (guard existing) |

**Architectural problems:** none structural. The single real conflict is the sync execution model
versus a spec sketch of `async` providers; resolved as a numbered decision (sync interface with
async companions). Second: business context has no home in the model, so the AI layer would be
forced to invent it — hence the profile table before any risk scoring.

**Missing tests:** no tests for failure paths of the AI layer (none exists), no test that
`ANS_AUTH_ENABLED=true` protects every route (partially covered in `tests/unit/test_security.py`),
no test for asset-scoped authorization (the capability itself is missing).

## 3. Implementation roadmap (this mission)

Order chosen so that every later feature consumes verified data from the previous step:

| Step | Deliverable | Exit check |
| --- | --- | --- |
| 1 | Schema: asset profile + repository metadata + sbom edges + EPSS + AI tables (`ai_executions`, `security_context_snapshots`, `risk_assessments`, `security_policies`, `security_investigations`, `investigation_evidence`, `remediation_recommendations`, `remediation_verifications`, `security_decisions`, `ai_feedback`, `assistant_*`) | `alembic upgrade head` + `downgrade` on scratch DB, tests green |
| 2 | Deterministic primitives: version comparators, EPSS model+sync, dependency-edge parsing, repository metadata, policy engine | unit tests per ecosystem; parser fixture test |
| 3 | AI foundation: provider (OpenAI-compatible), retries/rate-limit/budget, structured validation, prompt registry, execution ledger, redaction | offline tests with fake provider; no key needed |
| 4 | Context builder + snapshots (all six context sections, explicit missing info, hash stability) | unit + integration tests |
| 5 | Risk analyst: deterministic signals + policy scoring + AI assessment, append-only persistence | reproducibility test: same inputs ⇒ same deterministic score |
| 6 | Investigation: LangGraph workflow (load → context → intel → deps → AI → evidence → risk → persist), evidence citations | status vocabulary test, malformed-output test |
| 7 | Remediation: recommendation + patch proposal + approval state machine; verification: rescan + diff + policy | verification status derives only from scanner/DB evidence |
| 8 | Knowledge + assistant: decisions, feedback, typed read-only tools, asset-scoped authorization, audit | no SQL/shell/URL tool exists (test); scope-denial test |
| 9 | API + worker jobs + frontend surfaces (overview, finding AI panel, remediation center, assistant) | OpenAPI additive, `npm run build` green |
| 10 | Docs + CI + final verification with a real model on real findings | real analysis persisted for real findings, evidence cited |

## 4. Non-negotiables carried into implementation

1. AI never writes `findings.status`, never dismisses, never accepts risk, never touches a repo.
2. CVSS, deterministic score, AI assessment, final priority and AI confidence are five separate
   fields — never collapsed.
3. Every AI row is append-only and references a context snapshot + evidence ids.
4. Missing evidence lowers confidence, never risk; `NO_EVIDENCE_FOUND` is not "safe".
5. All model traffic goes through the provider abstraction; no business module imports a provider.
6. Deterministic work (matching, version maths, policy, verification) never calls a model.
