# Security model

This document is the threat model and the enforcement map for the platform
itself. `docs/SECURITY.md` covers deployment defaults; this one covers what the
code enforces.

## 1. Trust boundaries

| Input | Trust | Enforcement |
| --- | --- | --- |
| Repository content | untrusted | depth-1 clone, no submodules, hooks disabled, symlinks escaping the workspace removed, scanners are argv-only subprocesses |
| Scanner output (Trivy/Semgrep/Gitleaks/Syft/Checkov) | untrusted text | parsers validate shape, bounds and types; strings capped; secrets masked before persistence |
| Security telemetry (Falco, log shippers) | untrusted | shared sensor token (constant-time), body/batch/field limits, control characters stripped, raw payload truncated + redacted |
| Threat intelligence | untrusted | type validation (`ipaddress`, hash regex, URL scheme/host), length caps, exact-match storage |
| AI model output | untrusted | strict Pydantic schema, one repair attempt, then `INVALID_OUTPUT`; citations validated against supplied keys; no tool execution |
| API caller | authenticated or anonymous (dev only) | API key at router level, per-key asset scope, auth disabled only by explicit config |
| Container image reference | untrusted | registry allow-list, character allow-list, argv-only invocation |

Every external process is launched through `modules/scanners/execution.py`:
`shell=False`, sanitized environment (`ANS_*` and anything matching
TOKEN/SECRET/PASSWORD/API_KEY removed), `setsid`, process-group kill on timeout,
`RLIMIT_AS`/`NPROC`/`FSIZE`/`CORE` caps, bounded redacted stdout/stderr excerpts.

## 2. Authentication and authorization

* `ANS_AUTH_ENABLED=true` + `ANS_API_KEYS` (constant-time comparison). The
  principal is resolved once at router level; every route inherits it.
* Per-key asset scope: `ANS_API_KEY_SCOPES={"1": ["<asset-uuid>"]}`. A scoped
  principal may read only those assets, and **may not read unattributed
  telemetry** (`asset_id = NULL` events/incidents) — scoping cannot be bypassed
  by an event that failed asset resolution.
* Scope is applied in SQL for list endpoints (so `total` is honest), and per
  object for detail/mutation endpoints (404 rather than 403 to avoid confirming
  existence).
* Ingestion uses a separate sensor token, never a human API key. Webhooks use
  provider signatures (HMAC-SHA256 / constant-time token). Both are mounted
  outside the API-key router because those callers cannot send `X-API-Key`.
* There is no user database, OIDC, or RBAC role model. Multi-tenant isolation is
  asset-scope only; documented as a limitation, not implied.

## 3. Secrets and data handling

* Repository tokens are Fernet-encrypted (`ANS_SECRET_KEY` /
  `ANS_CREDENTIAL_KEY`); only a masked hint is returned by the API. Plaintext is
  decrypted only in the worker to build the clone header, never written to
  `.git/config`.
* `core.security.redact_text` masks token-shaped strings and URL credentials. It
  is applied to: scanner excerpts, event raw payloads and descriptions, code
  snippets, AI evidence, audit detail, and assistant input.
* Event raw payloads are truncated to 16 KiB (`enrichment.raw_truncated` marks
  truncation). Attacks do not get a free storage amplifier.
* AI evidence is fenced and labelled untrusted; prompts are not stored unless
  `ANS_AI_STORE_PROMPTS=true`; the execution ledger stores identifiers, tokens,
  cost and latency only.
* `raw` event payloads are exposed only on the event detail endpoint, and are
  already bounded/redacted at ingestion.

## 4. SSRF and egress

* Repository clone URLs are validated against `ANS_ALLOWED_GIT_HOSTS`; the branch
  name is validated; the URL is re-validated immediately before use.
* Container image references must match `^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,300}$`
  and the registry must be in `ANS_ALLOWED_IMAGE_REGISTRIES` (default
  docker.io/ghcr.io/quay.io). This prevents asking the worker to pull from an
  internal registry (a classic SSRF pivot through a scanner).
* Feed clients (OSV/NVD/KEV/EPSS) use fixed, configured URLs with timeouts and
  response size ceilings. No user-supplied URL is fetched.
* The AI provider URL is operator-configured, never model- or user-supplied.

## 5. Webhooks and ingestion

* GitHub: `X-Hub-Signature-256` HMAC over the raw body.
  GitLab: `X-Gitlab-Token` constant-time compare.
  Unset secret ⇒ `503`, not trust.
* Delivery rows are unique on `(provider, delivery_id)`: a replay is a no-op.
* Only push events to the asset's default branch enqueue work, and the HTTP
  request only enqueues — nothing is cloned inside the request.
* Event ingestion: unset token ⇒ `503`; wrong token ⇒ `401`; oversized body or
  batch ⇒ `422`; normalization failures are rejected per request, not partially
  persisted.

## 6. Audit

`audit_log` is append-only: there is no update/delete service or route. Two
writers:

1. `AuditMiddleware` — every mutating API request (`POST/PUT/PATCH/DELETE`) under
   `/api/v1`, recording actor, action, resource type/id, status, request id, IP
   and a bounded, redacted detail. The request **body is never recorded** (it can
   contain a token).
2. Domain services — incident transitions, investigations, ingestion counters,
   indicator batches, infrastructure scans, rule changes.

Audit failures never fail the action; they are logged. That trade-off is
deliberate and documented: availability of the security action is not conditioned
on the audit table, and a persistent audit failure is visible in logs.

## 7. AI guardrails (enforced in code)

| Guardrail | Enforcement | Test |
| --- | --- | --- |
| Evidence is untrusted | fenced EVIDENCE block + system rule | `test_event_rules`, `test_ai_workflow` |
| Secrets never reach the provider | redaction before evidence build | `test_redaction` |
| No invented citations | key allow-list; unknown keys dropped | `test_unknown_citations_are_dropped…` |
| No verdict from no evidence | `NO_EVIDENCE_FOUND` vocabulary; missing evidence lowers confidence | `test_incident_investigation` |
| No status/severity/priority change | AI writes only AI tables + timeline | `test_ai_investigation_persists_cited_report_and_ledger` |
| Failures labelled, not faked | `INCONCLUSIVE` + `error_code` | `test_provider_failure_is_recorded_not_faked` |
| No shell/SQL/URL tools | static assistant tool registry | `test_assistant_tools_are_read_only_and_scope_aware` |
| Cost bounded | rate limit, token caps, daily budget fail-closed | `test_ai_provider` |
| Cross-domain evidence bounded | aggregation caps at 12 groups + input char budget | `test_evidence_is_bounded_and_counts_are_aggregated` |

AI never: changes scanner findings, marks a vulnerability fixed, accepts risk,
executes containment, modifies infrastructure, or reconciles an incident. The
incident transition API is human/API-key driven only.

## 8. Database and queue safety

* One transaction per service operation; API dependency commits on success and
  rolls back on exception.
* Job claims use `SELECT … FOR UPDATE SKIP LOCKED`; retries use exponential
  backoff; stale heartbeats are requeued.
* Partial unique indexes prevent: two active scans per asset, two active
  infrastructure scans per target, duplicate deduplicated SBOMs, duplicate
  provider deliveries, duplicate `(source, source_event_id)` events.
* Every state-changing worker step commits before the next external call, so a
  crash leaves a visible `RUNNING/FAILED` row instead of a silent rollback.

## 9. Known weaknesses / accepted risks

| # | Risk | Status |
| --- | --- | --- |
| S1 | `ANS_SECRET_KEY` has a development default; rotating it invalidates stored tokens | documented, warned in `.env.example` |
| S2 | `ANS_AUTH_ENABLED=false` by default for local use | documented; must be enabled before exposure |
| S3 | No RBAC/SSO; scope is per API key | accepted for single-tenant self-hosting |
| S4 | Event retention is manual | accepted; operations runbook |
| S5 | Scanner sandboxing is resource-limited, not a kernel sandbox | accepted; run the worker on a dedicated host/VM |
| S6 | Audit writes are best-effort | accepted trade-off; monitor logs |
| S7 | `localhost`/private registries are blocked by default | intentional; add explicitly if required |

Report security issues privately to the maintainer rather than opening a public
issue with exploit details.
