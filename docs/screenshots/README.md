# Screenshots

This directory holds the screenshots referenced by the project README. They must
show the **real running application** — no mockups, no redesigned comps, no
invented data.

## Status

| File | Screen | Status |
| --- | --- | --- |
| `dashboard.png` | Security dashboard with the AI risk overview | captured |
| `findings-ai-panel.png` | Finding dialog, AI analysis → Risk tab (five scores + signal table) | captured |
| `remediation-center.png` | Remediation centre with proposals and lifecycle status | captured |
| `assistant.png` | Security assistant answering a grounded question | captured |
| `investigation.png` | AI investigation report with cited evidence | to capture |
| `sbom.png` | SBOM package inventory for one scan | to capture |

## How to capture

Run the stack (`docker compose up -d --build`) and use a desktop browser at
1440×900, dark colour scheme, zoom 100%:

| Screen | URL |
| --- | --- |
| Dashboard | `http://localhost:8080/` |
| Findings | `http://localhost:8080/findings` (click a row to open the AI panel) |
| Remediation | `http://localhost:8080/remediation` |
| Assistant | `http://localhost:8080/assistant` |
| Scans | `http://localhost:8080/scans` |
| SBOM | `http://localhost:8080/sboms` |

Guidelines:

- Use demo data you are allowed to publish. Never capture a customer repository,
  a real token, or a private asset name.
- Wait for data to load — a skeleton or "Could not load data" panel is not a
  screenshot.
- Prefer the state that shows evidence: a finding with a risk assessment, a
  proposal awaiting approval, an answer with tool results.
- Keep PNG under ~500 KB (resize to 1440 px wide if needed) so the README stays
  fast to load.

If a screen is not ready, leave it out of the table instead of adding a
placeholder image that looks like a product feature.
