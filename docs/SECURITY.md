# Security notes — scanner execution and repository handling

Repository content is **untrusted input**. So is the output of the scanners
that analyse it. This document lists the risks identified before implementation
and the controls that exist in the code today, plus the limits you must accept.

## Threat model

| # | Risk | Control |
| --- | --- | --- |
| 1 | Command injection through repository URL, branch or filename | All external commands are argv vectors with `shell=False`; URLs are parsed and validated (https only, host allow-list, no userinfo); branch names are regex-validated and cannot start with `-`; no user input is ever interpolated into a shell string |
| 2 | SSRF / cloning internal infrastructure | `ANS_ALLOWED_GIT_HOSTS` allow-list (default `github.com,gitlab.com`), scheme must be `https`, literal private/loopback IPs rejected |
| 3 | Credential theft from workspace | Token passed as an `http.extraHeader` (never in the URL), origin URL reset to the clean URL after clone, credentials stripped from the scanner environment, `ANS_*` variables removed |
| 4 | Secret values leaking into findings/UI | Gitleaks runs with `--redact`; matched values are masked again in the adapter; `redact_text()` masks GitHub/GitLab/AWS/Stripe/Slack/Google token patterns and `user:pass@` URL segments in any persisted stdout/stderr |
| 5 | Path traversal / symlink escape from the workspace | Scan runs in a per-scan directory; `core.hooksPath=/dev/null`; symlinks resolving outside the workspace (or into `.git`) are deleted before scanning; every storage key is validated and resolved under `ANS_STORAGE_ROOT` |
| 6 | Accidentally executing repository code | Only scanners run: `git clone`, `syft scan`, `trivy fs`, `semgrep scan`, `gitleaks detect`. None of them execute project builds, tests or scripts. Submodules are not fetched (`--no-recurse-submodules`) |
| 7 | Resource exhaustion (fork bombs, huge files, runaway scans) | Per-process `RLIMIT_AS`, `RLIMIT_FSIZE`, `RLIMIT_NPROC`, `RLIMIT_CORE`; wall-clock timeouts; process-group kill (`killpg`) on timeout; findings capped per scan; NVD pages capped; Semgrep parallelism limited by `ANS_SEMGREP_JOBS` |
| 8 | Untrusted scanner output crashing the pipeline | Parsers are defensive (missing keys, wrong types, empty reports, non-JSON output); malformed reports become a `FAILED` execution, not a crash; every parse error is logged with the scanner name |
| 9 | Prompt-injection style abuse via repository content | Repository text, scanner output and feed data are always passed in a fenced `EVIDENCE` block that the system prompt labels as untrusted data; instruction-like patterns are detected and recorded as `injection_markers` per evidence item; evidence can never change tool availability, output schema or permissions |
| 10 | Unauthorized API access | Optional API-key auth enforced at router level with constant-time comparison; `ANS_AUTH_ENABLED=true` is required before exposing the platform beyond localhost |
| 11 | Credential exposure in logs | Logging filters sensitive keys (`token`, `secret`, `password`, `authorization`, …); clone argv contains no token; sync clients never log headers |
| 12 | Privilege escalation via container | API/worker images run as an unprivileged user (`appuser`, uid 10001); scanners need no privileges since they only read files |
| 13 | Secrets or source code sent to an LLM provider | Every evidence string passes `redact_text()` (token patterns, `user:pass@` URLs) before it can reach a prompt; Gitleaks evidence is masked at capture; `ANS_AI_ALLOW_SOURCE_SHARING=false` disables snippets entirely; `ANS_AI_STORE_PROMPTS=false` by default, and stored prompts (opt-in) are redacted and capped |
| 14 | Model invents CVEs, versions or fixes | Prompts carry only authoritative fields; a proposed fixed version must appear in `fixed_versions` **and** pass the deterministic version comparator, otherwise it is discarded and recorded; evidence citations are validated against supplied keys and unknown keys are dropped |
| 15 | AI silently marking findings safe or fixed | The output schema cannot express "safe"; the strongest negative status is `NO_EVIDENCE_FOUND`; AI never writes `findings.status`; verification status is derived only from scan evidence; any AI failure is recorded as `deterministic_only` |
| 16 | Runaway model spend / provider outage | Per-minute token bucket, token caps, per-request timeout, bounded retries with jitter, daily budget that fails closed, bounded auto-analysis count; with AI disabled every AI mutation returns `503 ai_unavailable` and the rest of the platform is unaffected |
| 17 | Assistant used as a data-exfiltration or execution proxy | Fixed read-only tool registry (no SQL, shell, URL or filesystem tool), typed argument validation, `Principal.asset_scope` enforced per call, full transcript in `assistant_messages` |

## Deliberate limits

* **No per-scan network isolation.** Scanners may download rule/config data
  (Semgrep registry, Trivy DB). If you need egress control, run the worker in a
  network namespace/egress proxy and pre-seed the caches.
* **Rootless but same host.** The worker is isolated by process and filesystem
  directory, not by VM. A scanner zero-day could still read files the worker user
  can read. For hostile untrusted repositories, run the worker container with a
  read-only root filesystem, no host mounts and a strict seccomp profile.
* **Regex-based secret detection is imperfect.** Gitleaks false positives and
  false negatives exist; triage statuses exist for exactly that reason.
* **NVD/OSV data is untrusted** (it is public, third-party content). Records are
  stored as-received with source identifiers preserved; CVSS is only computed
  from published vectors.
* **API keys are static.** There is no user model or RBAC; asset-level scoping is
  configured per key (`ANS_API_KEY_SCOPES`). Rotate keys by editing `ANS_API_KEYS`
  and restarting the API.
* **The model provider is a trust boundary.** Anything sent to the provider leaves
  your infrastructure. Redaction removes credential-shaped strings, but source
  snippets are still your code: keep `ANS_AI_ALLOW_SOURCE_SHARING=false` for
  repositories you are not allowed to share, or point `ANS_AI_BASE_URL` at a
  self-hosted compatible endpoint.
* **Verification stops at scan evidence.** There is no deployment integration, so
  "verified fixed" means "the vulnerable version and finding are gone from a fresh
  scan", not "production is safe". The API says so explicitly.

## Deployment checklist

- [ ] `ANS_SECRET_KEY` (or `ANS_CREDENTIAL_KEY`) generated randomly and stored in
      a secret manager — changing it invalidates stored repository tokens.
- [ ] `ANS_AUTH_ENABLED=true` and non-trivial `ANS_API_KEYS` for anything that is
      not localhost.
- [ ] TLS terminated in front of the API (nginx/Caddy/ALB); the compose stack
      serves plain HTTP.
- [ ] `ANS_CORS_ORIGINS` restricted to the real dashboard origin.
- [ ] PostgreSQL not exposed publicly; strong password; backups encrypted.
- [ ] `ANS_STORAGE_ROOT` on encrypted storage if SBOMs are considered sensitive
      (they enumerate your dependencies).
- [ ] Worker resource limits set in compose (CPU/memory) in addition to the
      in-process rlimits.
- [ ] Log aggregation with retention; logs intentionally contain no secrets.
