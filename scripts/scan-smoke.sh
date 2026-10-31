#!/usr/bin/env bash
# End-to-end smoke test against a running instance.
#
#   ./scripts/scan-smoke.sh [API_BASE] [REPO_URL] [BRANCH]
#
# Registers (or reuses) a repository, triggers a scan, waits for completion and
# prints the scan summary plus the dashboard counters.
set -euo pipefail

API_BASE="${1:-http://localhost:8000}"
REPO_URL="${2:-https://github.com/OWASP/NodeGoat}"
BRANCH="${3:-master}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

exec python3 "${SCRIPT_DIR}/scan_smoke.py" --api "${API_BASE}" --repo "${REPO_URL}" --branch "${BRANCH}"
