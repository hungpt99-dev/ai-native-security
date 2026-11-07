# Runtime security

Runtime security is the domain that turns *telemetry from running systems* into
incidents a human can act on. It is deliberately not a log search product: every
event is normalized, deduplicated, matched against deterministic rules, and only
then correlated into an incident. A model is never shown a raw log stream.

```
sensor ──HTTP──▶ ingestion ──▶ normalize ──▶ dedupe ──▶ enrich ──▶ rules ──▶ incident
(Falco,                    (bounded,        (fingerprint,   (asset,     (signature,   (deterministic
 log shipper)               redacted)        occurrence)     threat intel) threshold)    risk + reuse)
```

## 1. Ingestion

Two endpoints, both **outside** the human API-key router, both authenticated by a
dedicated sensor token (`ANS_EVENTS_INGEST_TOKEN`). When the token is unset the
endpoints answer `503 service_unavailable` — an unconfigured ingestion path never
accepts anonymous telemetry.

| Endpoint | Body | Use |
| --- | --- | --- |
| `POST /api/v1/ingest/falco` | one Falco alert object, or an array | Falco `http_output` |
| `POST /api/v1/ingest/events` | `{"events": [...]}` | any sensor with the generic schema |

Limits: request body ≤ 2 MiB, batch ≤ `ANS_EVENTS_MAX_BATCH` (default 500),
strings bounded, control characters stripped, raw payload truncated to 16 KiB and
redacted, indicators capped at 20 per event. A rejected batch writes nothing.

Authentication: `X-ANS-Ingest-Token: <token>`, constant-time compared. There is
no fallback to the human API key.

### Generic event schema

```json
{
  "event_type": "auth.failure",
  "title": "Failed login",
  "description": "optional free text",
  "category": "IDENTITY",
  "severity": "LOW",
  "source_event_id": "sensor-side id (replay protection)",
  "occurred_at": "2026-11-07T06:40:00Z",
  "normalized": {
    "host": "api-01",
    "process": "sshd",
    "command_line": "sshd: admin [net]",
    "user": "admin",
    "file_path": "/var/log/auth.log",
    "remote_ip": "203.0.113.66",
    "remote_port": 22,
    "container": {"id": "...", "name": "api", "image": "ghcr.io/acme/api:1.2.3"},
    "pod": "api-7d9f",
    "namespace": "production",
    "rule_name": "vendor rule name",
    "hash": "sha256:...",
    "url": "https://...",
    "domain": "example.com"
  },
  "indicators": [{"type": "IP", "value": "203.0.113.66"}],
  "raw": {"any": "bounded original payload"}
}
```

`category` ∈ `RUNTIME`, `NETWORK`, `IDENTITY`, `INFRASTRUCTURE`, `APPLICATION`,
`DATA`. `severity` ∈ the platform's six levels. Unknown keys are ignored; unknown
category/severity values are rejected (`422`).

### Falco

Falco's `http_output` is enough — no agent, no daemon, no socket:

```yaml
# /etc/falco/falco.yaml
http_output:
  enabled: true
  url: http://security-api:8000/api/v1/ingest/falco
  user_agent: "falcosecurity/falco"
  insecure: false
  # Falco 0.38+ supports custom headers:
  # headers: {X-ANS-Ingest-Token: "<ANS_EVENTS_INGEST_TOKEN>"}
```

If your Falco build cannot set headers, put a small authenticated reverse proxy in
front of the endpoint; do not disable the token. `priority` maps explicitly:
emergency/alert/critical → CRITICAL, error → HIGH, warning → MEDIUM, notice → LOW,
informational/debug → INFO, anything else → UNKNOWN (never silently HIGH).

Rule tags `network`, `k8s_audit`/`aws_cloudtrail` move an event to the NETWORK /
IDENTITY category; everything else is RUNTIME.

## 2. Normalization and deduplication

`modules/events/normalize.py` produces one canonical document per event. Every
field is optional: a missing remote port is absent, not zero, and rules simply do
not match.

Identity is a SHA-256 over `source | event_type | asset | category | primary
entity`. The primary entity is the first available of process, command line,
file, remote address/port, hash, domain, user, container. Consequences:

* the same detection firing 500 times is **one** row with
  `occurrence_count = 500` and `first_seen_at`/`last_seen_at`;
* a different process or file is a different event;
* a sensor retry with the same `source_event_id` is a no-op (unique partial index
  on `(source, source_event_id)`), so an at-least-once delivery cannot inflate
  counts.

This is what makes correlation and AI evidence affordable: the model sees
`"nsenter executed 37 times"`, not 37 log lines.

## 3. Asset resolution

An event is attached to an inventory asset by, in order:

1. an explicit asset id (generic ingestion may include one);
2. container image → `docker://<image>` (`CONTAINER_IMAGE` asset);
3. host → `host://<host>` (`HOST` asset).

When `ANS_EVENTS_AUTO_CREATE_ASSETS=true` (default) an unknown image/host is
registered with `provider=NONE` and `description="Auto-discovered from security
telemetry"`. The batch cap (`ANS_EVENTS_MAX_AUTO_ASSETS_PER_BATCH`, 50) prevents
an event flood from creating unbounded rows. An unresolved event keeps
`asset_id = NULL` and records `enrichment.asset.reason`, which is visible in the
API and UI — it is never guessed.

## 4. Detection rules

Rules are data. `detection_rules.conditions` is a small DSL, validated on write
and never executed as code:

```json
{"all": [
  {"field": "normalized.container.image", "op": "exists", "value": true},
  {"field": "normalized.process", "op": "in", "value": ["bash", "sh"]}
]}
```

Groups: `all`, `any`, `not` (nestable). Operators: `exists`, `eq`, `ne`, `in`,
`not_in`, `contains`, `not_contains`, `startswith`, `endswith`, `regex`, `gt`,
`gte`, `lt`, `lte`, `in_cidr`, `any_in`. Fields are an allow-list; `in_cidr` uses
`ipaddress`, not string prefixes; regexes are length-capped.

Built-in rules (seeded at startup, idempotent, versioned):

| Slug | Detects | Severity | Incident |
| --- | --- | --- | --- |
| `runtime.shell_in_container` | interactive shell in a container | HIGH | no |
| `runtime.package_manager_in_container` | package install in a running container | MEDIUM | no |
| `runtime.sensitive_file_access` | credential file access | HIGH | no |
| `runtime.crypto_mining` | miner binary / mining pool in command line | CRITICAL | yes (P2) |
| `runtime.reverse_shell` | reverse-shell construction | CRITICAL | yes (P2) |
| `runtime.privilege_escalation` | setuid / privileged command | HIGH | no |
| `runtime.container_escape` | escape-class Falco rule names | CRITICAL | yes (P1) |
| `network.suspicious_ports` | connection to commonly abused ports | MEDIUM | no |
| `identity.repeated_auth_failure` | ≥10 failures / 5 min / same IP | HIGH | yes (P2) |
| `runtime.critical_falco_event` | any CRITICAL Falco alert | CRITICAL | yes (P1) |
| `runtime.event_rate_anomaly` | statistical baseline deviation (job) | MEDIUM/HIGH | no |

Built-in rule **conditions** are immutable through the API; an operator can
disable them or change severity. Customisation that needs different logic is a
CUSTOM rule with its own slug, so a detection always explains itself with the
rule version it matched (`security_events.rule_slug` + `rule_version`).

### Threshold rules

A threshold rule requires `threshold = {"count": N, "window_seconds": W,
"group_by": ["normalized.remote_ip"]}`. Evaluation is bounded by
`ANS_EVENTS_THRESHOLD_SCAN_LIMIT` (5000 rows) and by the window. **Grouping is
applied before counting**: ten failures from ten different addresses are ten
separate low-signal events, not a password-spraying incident. A rule with a
`group_by` field absent from the triggering event cannot fire.

### Anomaly detection

`RUNTIME_ANOMALY_SCAN` (daily, `ANS_EVENTS_ANOMALY_INTERVAL_MINUTES`) compares
the last 24 h with the mean daily rate of the preceding
`ANS_EVENTS_ANOMALY_BASELINE_DAYS` days for each `(asset, event_type)` pair:

* needs `ANS_EVENTS_ANOMALY_MIN_COUNT` events (default 20) before it can fire;
* fires above `baseline_mean × ANS_EVENTS_ANOMALY_MULTIPLIER` (default 4);
* with no history at all, the threshold is raised to `min_count × 2.5` and the
  event records `baseline_days: 0` — the baseline was not established.

The output is one `anomaly.event_rate` event per asset/type/day with
`enrichment.anomaly = {recent_count, baseline_daily_mean, baseline_days, ratio,
threshold}`. It is arithmetic, not a model.

## 5. Incidents

A rule with `create_incident=true` (or a threshold hit) opens an incident, or
attaches to the open one with the same `correlation_key`
(`rule_slug:asset`), within `ANS_INCIDENT_REUSE_WINDOW_HOURS` (24 h). Reuse is why
a recurring detection produces one incident with a timeline, not one per alert.

Deterministic incident risk (`modules/incidents/risk.py`, `incident-risk/1`):

| Factor | Contribution |
| --- | --- |
| worst event severity | CRITICAL 85, HIGH 65, MEDIUM 45, LOW 25, INFO 10 |
| asset criticality | CRITICAL +10, HIGH +7, MEDIUM +4 |
| internet exposure | +5 |
| threat-intel match (confidence ≥70 / lower) | +10 / +5 |
| evidence volume | `min(5, log2(event_count + 1))` |

Score is capped at 100. Priority bands: ≥85 P1, ≥65 P2, ≥40 P3, else P4. A rule's
declared priority can raise this, never lower it. The legal status machine is in
`core/enums.py` (`OPEN → TRIAGING → INVESTIGATING → CONTAINED → RESOLVED →
CLOSED`, plus reopening), enforced by the service, and every transition writes a
timeline row with actor and note.

On creation the incident also links up to 10 active HIGH/CRITICAL findings on the
same asset (`reason=same_asset_high_severity`). `POST /incidents/{id}/correlate`
additionally attaches:

* events on the same asset within ±24 h that have no incident yet (max 50);
* findings sharing a CVE with an already-linked finding, across assets — the
  supply-chain blast radius.

## 6. Threat intelligence matching

Indicators are stored normalized (canonical IP, lowercase domain/hash) and matched
exactly on ingest. A match is written to `enrichment.threat_matches` with its
source, confidence and severity, and contributes to the event's deterministic risk
score. Expired indicators (`expires_at`) never match. There is no third-party
lookup at match time — a match is always attributable to a stored source.

## 7. What is not implemented (and is not faked)

* **No network sensor.** The `NETWORK` category accepts events from an external
  sensor (Zeek/Suricata export, cloud flow logs) through the generic endpoint.
  The platform does not capture packets.
* **No identity-provider integration.** `IDENTITY` events come from the generic
  endpoint or Falco's audit plugins. There is no directory sync or login
  correlation beyond event matching.
* **No RASP / in-process agent.** Application behaviour is observed through
  structured logs and runtime events, not instrumentation.
* **No automatic containment.** Incident response actions are recommendations;
  the platform has no shell, cloud or orchestrator credentials.
* **Retention** is not automatic. Events are kept indefinitely; an operator
  should schedule a retention job for their environment (see `OPERATIONS.md`).

These are deliberate boundaries, reported by the platform rather than hidden:
`GET /monitoring/health` marks event ingestion `DISABLED` when no token is
configured and `UNKNOWN` when it has never received an event.
