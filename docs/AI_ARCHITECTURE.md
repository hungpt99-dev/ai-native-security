# AI Architecture

The platform is AI-native in one specific sense: AI participates in the security
workflow, consumes structured evidence, and produces structured output that a
human can audit. It does not decide whether something is fixed, does not write to
the scanner's tables, and never touches a repository.

> **AI proposes. Evidence disposes.**

## 1. Layers and code

```
Layer 5  knowledge_base/        decisions, feedback, assistant transcripts
Layer 4  security_policies/     versioned policy documents (risk, remediation, data sharing)
         remediation/           proposals + approval lifecycle
         verification/          deterministic post-fix verification
Layer 3  ai/                    providers, prompts, agents, workflows, ledger, assistant tools
Layer 2  security_intelligence/ context builder, dependency graph, versions, snippets
Layer 1  assets, scans, scanners, sbom, vulnerabilities, findings   (unchanged)
```

| Concern | Module | Deterministic? |
| --- | --- | --- |
| CVE matching, correlation, dedup, lifecycle | `vulnerabilities/`, `findings/` | yes |
| Version comparison / range maths | `security_intelligence/versions.py` | yes |
| Dependency graph extraction & analysis | `scanners/syft.py`, `security_intelligence/dependency_graph.py` | yes |
| Repository facts (languages, manifests) | `security_intelligence/repository_metadata.py` | yes |
| Code evidence capture | `security_intelligence/snippets.py` | yes |
| Context assembly | `security_intelligence/context_builder.py` | yes |
| Risk signals + policy blend | `risk_analysis/signals.py`, `risk_analysis/policy.py` | yes |
| Remediation version validation | `remediation/service.py` | yes |
| Verification status | `verification/service.py` | yes |
| Risk opinion, investigation report, remediation prose/patch, assistant answer | `ai/agents/*`, `ai/services/assistant.py` | no |

The four probabilistic operations are the only places a model is called. Each one
persists its output append-only, next to the deterministic data it was reasoning
about.

## 2. Request lifecycles

### Risk assessment (`POST /findings/{id}/risk-assessment`)

```
finding ──▶ context snapshot ──▶ deterministic signals ──▶ AI (optional) ──▶ policy blend ──▶ risk_assessments
                  │                      │                      │                 │
            evidence_hash          score + coverage      risk_score/conf    final_score/level
```

1. `SecurityContextBuilder` collects finding, asset, repository, dependency,
   vulnerability (OSV/NVD/KEV/EPSS), business and history sections, redacts every
   piece of evidence and records what is missing.
2. `compute_signals` produces eight weighted signals. Unknown signals contribute a
   neutral 0.5 and reduce *coverage* — never the score.
3. If AI is enabled and the severity gate allows it, the risk analyst returns a
   structured assessment. Failure is recorded and the run continues.
4. `policy.combine` blends deterministic and AI scores using the active policy
   version and derives the final band from the blended score.
5. Five numbers are stored separately: `cvss_score`, `deterministic_score`,
   `ai_risk_score`, `final_score`, `confidence`.

### Investigation (`POST /findings/{id}/investigation`)

A LangGraph state machine (`ai/workflows/investigation.py`):

```
START → load_context → compute_signals → investigate ─┬─▶ persist → END
                                       ▲              │
                                       └── retry ◀────┘  (retryable provider error, max 2)
```

* Each node records its name and duration in the workflow trace.
* The model must cite evidence keys (`E1`, `E2`, …). Citations that were not
  supplied are dropped; an impact claim with no surviving citation is downgraded
  to `NEEDS_MANUAL_REVIEW`.
* Statuses are limited to `CONFIRMED_IMPACT`, `POTENTIAL_IMPACT`,
  `NO_EVIDENCE_FOUND`, `INCONCLUSIVE`, `NEEDS_MANUAL_REVIEW`. `NO_EVIDENCE_FOUND`
  is explicitly not "safe".
* A run without a provider persists `INCONCLUSIVE` with
  `ai_unavailable_for_investigation` — never a fabricated conclusion.

### Remediation (`POST /findings/{id}/remediation`)

The model proposes; the platform validates:

* `recommended_version` must appear in the authoritative `fixed_versions` for that
  package **and** pass `is_fixed_version_valid()` (comparator per ecosystem). A
  version the data does not support is discarded and recorded as
  `recommended_version_rejected`.
* Patches are capped and labelled `unified-diff`; they are proposals only.
* The proposal enters the lifecycle at `REMEDIATION_PROPOSED` and immediately
  moves to `AWAITING_APPROVAL`; nothing is applied.

### Verification (`POST /remediations/{id}/verify`)

1. Recommendation → `VALIDATING`, a normal scan is queued (`scans.service.create_scan`).
2. When that scan completes, `workers/pipeline.py` calls
   `verification.on_scan_completed`.
3. The engine compares the verification scan's SBOM and findings with the
   recording: package version before/after, whether the finding survived, and how
   many new high/critical findings appeared.
4. Status is one of `VERIFIED_FIXED`, `STILL_VULNERABLE`, `PARTIALLY_FIXED`,
   `NEW_RISK_INTRODUCED`, `VERIFICATION_FAILED`. New high/critical findings above
   the policy threshold take precedence over a "fixed" result.
5. `POST /verifications/{id}/explain` may attach an AI explanation afterwards; it
   cannot change `status`.

### Assistant (`POST /ai/assistant/ask`)

```
question ─▶ plan (model, tool catalogue) ─▶ execute whitelisted read-only tools ─▶ answer (model, tool rows as evidence)
```

Ten tools exist, all typed with Pydantic arguments and all read-only:
`platform_overview`, `list_findings`, `finding_details`, `top_risk_assets`,
`asset_overview`, `kev_findings`, `remediation_queue`, `recent_scans`,
`decision_history`, `search_knowledge`. There is no SQL, shell, URL or filesystem
tool anywhere in the registry, and `Principal.asset_scope` is enforced per call.

## 3. Data model

| Table | Purpose |
| --- | --- |
| `security_context_snapshots` | frozen context per finding, with `evidence_hash` |
| `ai_executions` | one row per model call: prompt/schema versions, tokens, cost, duration, status |
| `risk_assessments` | append-only assessments (CVSS / deterministic / AI / final / confidence) |
| `security_investigations` + `investigation_evidence` | investigation runs and their cited evidence |
| `remediation_recommendations` | proposals, deterministic version validation, approval state |
| `remediation_verifications` | before/after versions, scan ids, policy result, status |
| `security_decisions` | immutable human decisions with reasons |
| `ai_feedback` | structured feedback on AI artefacts (no fine-tuning) |
| `assistant_conversations` + `assistant_messages` | transcripts including tool calls and rows |
| `security_policies` | versioned scoring/remediation/data-sharing policy documents |
| `asset_security_profiles` | business context (criticality, exposure, environment, owner) |
| `asset_repository_metadata` | languages, frameworks, manifests derived from scans |
| `sbom_package_edges` (+ `sbom_packages.is_direct`) | dependency graph |
| `vulnerability_epss` | EPSS probability per CVE |

Append-only tables are read as "current" with `ORDER BY created_at DESC LIMIT 1`.
No `is_current` flags: one query instead of permanent consistency work.

## 4. Guardrails and where they are enforced

| Guardrail | Enforcement | Test |
| --- | --- | --- |
| Evidence is untrusted | fenced `EVIDENCE` block + system rule | `test_untrusted_evidence_is_fenced` |
| Secrets never reach the provider | `core.security.redact_text` at evidence build + `sanitize()` | `test_ai_workflow` (redaction), `test_redaction` |
| Injected instructions are visible | `injection_markers` per evidence item | `test_prompt_injection_markers` |
| No invented fixed versions | `is_fixed_version_valid` + membership check | `test_remediation_rejects_a_version_the_data_does_not_support` |
| No hallucinated citations | evidence-key allow-list, dropped otherwise | `test_unsupported_citations_are_dropped_and_downgraded` |
| CVSS is never overwritten | AI writes only AI tables | `test_risk_assessment_keeps_five_numbers_separate` |
| Missing data ⇒ lower confidence, not lower risk | neutral 0.5 + coverage-based confidence | `test_risk_assessment_without_ai_is_explicitly_deterministic` |
| Failures are labelled, never faked | `deterministic_only` + `ai_unavailable_*` entries | `test_provider_failure_still_persists_a_labelled_assessment` |
| No status change by AI | findings/remediation transitions live in services | `test_approval_lifecycle_records_a_decision` |
| Asset-level authorization | `Principal.asset_scope` in AI endpoints and tools | `test_asset_scope_is_enforced_on_ai_endpoints` |
| No SQL/shell tools | static tool registry | `test_assistant_tools_are_read_only_and_scope_aware` |
| Malformed model output fails closed | strict Pydantic validation, one repair, then `INVALID_OUTPUT` | `test_invalid_output_twice_fails_closed` |
| Cost is bounded | per-minute rate limit, token caps, daily budget (fail closed) | `test_rate_limit_exhaustion_maps_to_rate_limited` |

## 5. Provider configuration

Any OpenAI-compatible endpoint works:

```bash
ANS_AI_ENABLED=true
ANS_AI_PROVIDER=openai
ANS_AI_BASE_URL=https://api.openai.com/v1      # or a gateway
ANS_AI_MODEL=gpt-4.1-mini
ANS_AI_API_KEY=...
ANS_AI_EXTRA_HEADERS={"x-session":"ai-native-security"}   # if the gateway needs it
ANS_AI_DAILY_BUDGET_USD=5
```

`GET /api/v1/ai/health` reports whether a provider is configured, the model, the
capabilities, today's spend and token counts — never the key. With
`ANS_AI_ENABLED=false` every AI mutation returns `503 ai_unavailable` and the rest
of the platform behaves exactly as before.

Cost is taken from the provider's `usage.cost` when present, then a gateway
`list_cost` field, then the configured price table, and is otherwise stored as
`NULL` rather than guessed.

## 6. Observability

Every call writes an `ai_executions` row (success **and** failure) with: kind,
provider, model, prompt id/version/hash, schema version, tokens, cost, latency,
attempts, request id, error code, and the principal. `GET /api/v1/ai/executions`
pages them. Prompts, evidence text and credentials are never stored there.

## 7. Known limitations

* Verification needs a completed scan. Deployment verification is out of scope in
  this environment: there is no deployment integration, and the platform says so
  instead of implying production confirmation.
* Runtime telemetry (RASP, traffic) is not integrated; every context includes
  `runtime_context_unavailable`.
* Reachability is bounded by the snippet captured at scan time. Without a call
  site the honest answer is `NO_EVIDENCE_FOUND`/`POTENTIAL_IMPACT`, not a verdict.
* Dependency edges are stored from the SBOM when the generator emits them. The
  Syft version used here produces CycloneDX **without** a `dependencies` section
  for directory scans, so most repositories report
  `dependency_graph_unavailable` and the directness signal stays unknown. The
  parser, table and analysis are in place and will populate as soon as a generator
  (or a future Syft release / `--enrich` mode) emits relationships. This is
  reported to the model as a gap, never guessed.
* The provider interface is synchronous (the application is). Async companions
  delegate to the same code path.
* Retrieval is SQL-based; no vector database is used, and none is required yet.
