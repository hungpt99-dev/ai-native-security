# Roadmap and capability status

Status vocabulary, used consistently in this file and in `FEATURE_AUDIT.md`:

* **IMPLEMENTED** — working code, migration, API, tests; exercised end to end.
* **PARTIAL** — a real, tested foundation exists but the stated capability is not
  complete (explicitly described).
* **PLANNED** — designed only; no misleading UI or placeholder endpoint.
* **BLOCKED** — cannot be completed in this environment (credentials,
  infrastructure, external system); the reason is stated.

Last verified: 2026-11-07, against `docker compose` with PostgreSQL, the API,
worker, scheduler and frontend running, plus 326 backend tests and a production
frontend build.

## 1. Application security

| Capability | Status | Notes |
| --- | --- | --- |
| SAST (Semgrep), dependency scan (Trivy fs), secret scan (Gitleaks), SBOM (Syft) | IMPLEMENTED | hardened subprocess layer, fingerprints, lifecycle |
| Vulnerability intelligence (OSV, NVD, CISA KEV, EPSS) | IMPLEMENTED | keyed by `(source, source_id)`, CVSS computed from vectors |
| Finding normalization, dedup, lifecycle, evidence | IMPLEMENTED | per-asset identity, history, bounded redacted snippets |
| Continuous SBOM lifecycle, diff, reassessment | IMPLEMENTED | no clone for reassessment, lineage-linked snapshots |
| AI risk assessment, investigation, remediation proposal | IMPLEMENTED | five separate score fields, cited evidence |
| Independent verification (post-fix rescan) | IMPLEMENTED | deterministic statuses only |
| Repository metadata (languages, frameworks, manifests) | IMPLEMENTED | derived from SBOM + bounded workspace walk |
| Cross-file call graph / reachability / taint analysis | PLANNED | not implemented; no false claims in UI. Snippet-level evidence only |
| Application architecture discovery (services, entry points) | PARTIAL | manifests + language inventory; no call graph or service map |
| API security discovery and assessment | PARTIAL | API-ish assets can be inventoried and monitored through events; no OpenAPI import or API fuzzing |
| Security regression detection (new vs baseline) | PARTIAL | new/resolved per scan, SBOM diff; no policy-based regression gate |
| Pull request security integration | PLANNED | webhooks enqueue scans; no PR check/status API or inline comments |

## 2. Software supply chain

| Capability | Status | Notes |
| --- | --- | --- |
| SBOM generation (CycloneDX/SPDX), storage, history | IMPLEMENTED | immutable documents, content-addressed keys |
| Dependency graph (direct/transitive) | PARTIAL | parser/table/analysis implemented; Syft directory scans emit no `dependencies`, so most repos report the graph as unavailable instead of guessing |
| Package → vulnerability correlation | IMPLEMENTED | exact-version OSV batch + stored-intel reassessment |
| License compliance | PLANNED | package metadata is stored; no license policy engine |
| Package provenance / signatures (Sigstore, SLSA) | PLANNED | not implemented |
| Container image dependency inventory | PARTIAL | `trivy-image` inventories OS packages and vulnerabilities; no image SBOM document per digest yet |
| Supply-chain risk assessment | PARTIAL | CVSS/EPSS/KEV + asset context + reachability signals; no provenance scoring |

## 3. Infrastructure and cloud security

| Capability | Status | Notes |
| --- | --- | --- |
| IaC scanning (Terraform, Dockerfile, K8s manifests) | IMPLEMENTED | Trivy config, optional Checkov (`INSTALL_CHECKOV=true`) |
| Container image vulnerability assessment | IMPLEMENTED | `trivy-image`, registry allow-list, findings in the shared pipeline |
| Infrastructure asset inventory + relationships | IMPLEMENTED | unified `assets` table (`kind`, `external_ref`, `parent_asset_id`) |
| Scheduled infrastructure assessment | IMPLEMENTED | per-asset interval, container images automatic |
| Kubernetes cluster assessment | PLANNED | manifests can be scanned as IaC; no cluster API integration |
| Cloud configuration assessment (AWS/GCP/Azure) | PLANNED | no cloud credentials or collectors |
| IAM misconfiguration detection | PLANNED | would require cloud/IAM data |
| Public exposure detection | PARTIAL | `asset_security_profiles.internet_exposed` feeds risk; no automated exposure discovery |
| Configuration drift detection | PLANNED | no baseline/drift engine |

## 4. Runtime security

| Capability | Status | Notes |
| --- | --- | --- |
| Event ingestion (Falco + generic), normalization, dedupe | IMPLEMENTED | sensor token, bounded bodies, occurrence counters |
| Rule-based detection (signature + threshold) | IMPLEMENTED | 11 built-in rules, versioned, DSL-validated |
| Asset enrichment + auto-discovery | IMPLEMENTED | image/host, batch-capped |
| Anomaly detection | IMPLEMENTED | deterministic baseline, cold-start explicit |
| Event correlation → incidents | IMPLEMENTED | reuse window, timeline, deterministic risk |
| Threat-intel enrichment of events | IMPLEMENTED | exact matching, expiry-aware |
| Container/process activity monitoring | PARTIAL | depends on Falco being deployed; the platform ingests, it does not host the sensor |
| Suspicious process / network / file detection | IMPLEMENTED | as rules over Falco/normalized fields |
| Privilege escalation indicators | IMPLEMENTED | rule-based |
| Runtime vulnerability exposure | PARTIAL | inventory findings exist; no runtime package-vs-host mapping |
| Application behaviour anomaly detection | PARTIAL | per-event-rate baseline, not per-endpoint behavioural models |
| OpenTelemetry ingestion | PLANNED | structured logs/generic events only |

## 5. Network security

| Capability | Status | Notes |
| --- | --- | --- |
| Network exposure inventory | PARTIAL | hosts/services are inventory assets; no port scan (deliberate) |
| Suspicious connection detection | IMPLEMENTED | via normalized events + rules + threat intel IPs |
| Unexpected outbound traffic | PARTIAL | rule-based on ports/destinations; no learned egress baseline |
| Service-to-service visibility | PLANNED | needs a sensor/eBPF or mesh telemetry |
| Network event correlation | IMPLEMENTED | shared event model, incidents by asset/time |

## 6. Identity and access

| Capability | Status | Notes |
| --- | --- | --- |
| Identity/service-account inventory | PLANNED | no directory or cloud IAM integration |
| Excessive permissions detection | PLANNED | needs IAM data |
| Suspicious login / credential misuse indicators | PARTIAL | `auth.failure` threshold rule + threat-intel IP matching |
| Access policy violations | PLANNED | no policy source |

## 7. Threat intelligence

| Capability | Status | Notes |
| --- | --- | --- |
| Vulnerability intel sources (OSV/NVD/KEV/EPSS) | IMPLEMENTED | freshness tracked in monitoring health |
| IOC ingestion (IP/DOMAIN/URL/SHA256/MD5/EMAIL) | IMPLEMENTED | normalized, validated, attributed, expiring |
| Indicator matching on events | IMPLEMENTED | exact, source-attributed |
| Source management / freshness | IMPLEMENTED | `/threat-intel/summary`, health component |
| Historical intelligence | PARTIAL | rows are retained; no temporal query UI |
| External IOC feed connectors (MISP, OpenCTI) | PLANNED | batch API is the integration point |

## 8. Data security

| Capability | Status | Notes |
| --- | --- | --- |
| Sensitive data in repositories | PARTIAL | Gitleaks secret findings + redaction |
| Sensitive data access monitoring | PARTIAL | runtime file-access events and rules; no DLP |
| Data exposure risks | PLANNED | no classification engine |
| Exfiltration indicators | PARTIAL | network rules + threat intel; no volume baseline |

## 9. Platform core

| Module | Status | Notes |
| --- | --- | --- |
| Asset management | IMPLEMENTED | repository + infra kinds, ownership/criticality profile, relationships |
| Security events | IMPLEMENTED | ingestion, normalization, dedupe, enrichment, lifecycle, notes |
| Finding management | IMPLEMENTED | unified schema across scanners/infra/runtime-adjacent findings |
| Risk engine | IMPLEMENTED | deterministic signals + versioned policy + optional AI, five separate numbers |
| Security monitoring health | IMPLEMENTED | evidence-based component statuses |
| Threat correlation | IMPLEMENTED | asset/time/CVE/indicator correlation, evidence preserved |
| Incident management | IMPLEMENTED | lifecycle, timeline, assignment, notes, correlation, AI investigation |
| Policy management | IMPLEMENTED | versioned risk/remediation/data-sharing policies (existing module) |
| Remediation management | IMPLEMENTED | proposal, approval, verification, reopening |
| Audit and compliance | PARTIAL | append-only audit + exports of findings/SBOM; no compliance framework mapping (SOC2/ISO) |
| Reports / compliance evidence export | PARTIAL | existing report endpoints for findings/SBOM; no scheduled report packs |

## 10. AI intelligence layer

| Capability | Status | Notes |
| --- | --- | --- |
| Provider abstraction (OpenAI-compatible, self-hosted) | IMPLEMENTED | retries, rate limit, budget, ledger |
| Vulnerability analysis / risk agent | IMPLEMENTED | structured, cited |
| Investigation agent (finding) | IMPLEMENTED | LangGraph workflow, bounded retry |
| Incident investigation agent (cross-domain) | IMPLEMENTED | aggregated evidence, citation validation, append-only |
| Remediation agent | IMPLEMENTED | version validated against authoritative data |
| Assistant | IMPLEMENTED | typed read-only tools, asset scope |
| Anomaly analysis agent | PARTIAL | anomaly detection is deterministic; no separate model agent for anomalies |
| Infrastructure security agent | PARTIAL | findings can be investigated with the existing finding agent; no IaC-specific prompt |
| Runtime threat investigation agent | IMPLEMENTED | incident investigation |
| Prompt versioning, cost tracking, execution ledger | IMPLEMENTED | every call, success and failure |
| Feedback / learning loop | IMPLEMENTED | decisions + structured AI feedback (no fine-tuning) |
| Vector retrieval | PLANNED | SQL retrieval only; no vector DB required yet |

## 11. Frontend

| Surface | Status |
| --- | --- |
| Security overview (incidents, events, health, posture) | IMPLEMENTED |
| Monitoring (events, filters, detail, detection rules, health) | IMPLEMENTED |
| Incidents list + detail (timeline, evidence, AI report, lifecycle) | IMPLEMENTED |
| Infrastructure (assets, scans, scanner availability) | IMPLEMENTED |
| Assets, scans, findings, SBOMs, intelligence, remediation, assistant, operations | IMPLEMENTED (existing, preserved) |
| Policies/settings authoring UI | PARTIAL (existing policy API; UI limited) |
| Threat-intel indicator management UI | PLANNED (API only) |
| Audit log UI | PLANNED (API only) |

## 12. Deliberate non-goals for this iteration

Kafka, Redis, Kubernetes, microservices, a custom OS agent, packet capture,
cloud IAM collectors, and an SSO/RBAC stack. Each would add operational surface
without a demonstrated requirement in a single-tenant self-hosted deployment. The
module boundaries and job queue are shaped so they can be extracted later without
rewriting business logic.

## 13. Next increments (ordered by evidence value)

1. Pull-request gate: GitHub check run + inline comment from the existing diff
   evidence (the webhook infrastructure already records deliveries).
2. License policy over stored SBOM metadata (CycloneDX licenses are already
   present in the document).
3. K8s audit-log ingestion mapped into the identity event category (no cluster
   credentials required — a log shipper posts to the generic endpoint).
4. Incident report export (Markdown/JSON) with cited evidence for handover.
5. Retention + archival job for `security_events` and `audit_log`.
6. Threat-intel CSV/STIX import on top of the existing batch API.
7. Frontend surfaces for audit and indicators.
