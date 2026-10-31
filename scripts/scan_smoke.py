#!/usr/bin/env python3
"""End-to-end smoke test for a running AI-Native Security Platform instance.

Registers (or reuses) a repository, triggers a scan, waits for completion and
prints the summary. Exit code 0 only when the scan completed successfully.

    python scripts/scan_smoke.py --api http://localhost:8000 \
        --repo https://github.com/OWASP/NodeGoat --branch master
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT_SECONDS = 40
POLL_INTERVAL = 5
MAX_WAIT_SECONDS = 1800


def request(method: str, url: str, payload: dict | None = None) -> dict:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310 - operator supplied URL
            body = response.read().decode()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        raise SystemExit(f"{method} {url} -> HTTP {exc.code}: {body[:400]}") from exc


def wait_for_health(base: str) -> None:
    for path in ("/healthz", "/readyz"):
        request("GET", f"{base}{path}")


def print_scanners(api: str) -> None:
    for item in request("GET", f"{api}/system/scanners"):
        state = "ready" if item.get("available") else "MISSING"
        detail = item.get("version") or item.get("error") or ""
        source = item.get("source") or ""
        print(f"  {item.get('scanner', '?'):<9} {state:<8} {detail[:60]:<60} {source}")


def ensure_asset(api: str, name: str, repo: str, branch: str) -> str:
    query = urllib.parse.urlencode({"search": name, "page_size": 1})
    existing = request("GET", f"{api}/assets?{query}")
    for item in existing.get("items") or []:
        if item.get("repo_url", "").rstrip("/") == repo.rstrip("/"):
            print(f"  reusing asset {item['id']}")
            return str(item["id"])
    created = request(
        "POST",
        f"{api}/assets",
        {"name": name, "repo_url": repo, "default_branch": branch},
    )
    print(f"  created asset {created['id']}")
    return str(created["id"])


def wait_for_scan(api: str, scan_id: str) -> dict:
    deadline = time.time() + MAX_WAIT_SECONDS
    status = "PENDING"
    while time.time() < deadline:
        scan = request("GET", f"{api}/scans/{scan_id}")
        status = scan.get("status", "PENDING")
        if status in {"COMPLETED", "FAILED", "CANCELED"}:
            return scan
        time.sleep(POLL_INTERVAL)
    raise SystemExit(f"scan {scan_id} did not finish within {MAX_WAIT_SECONDS}s (last status {status})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default="http://localhost:8000", help="API base URL (without /api/v1)")
    parser.add_argument("--repo", default="https://github.com/OWASP/NodeGoat")
    parser.add_argument("--branch", default="master")
    parser.add_argument("--name", default=None)
    args = parser.parse_args()

    base = args.api.rstrip("/")
    api = f"{base}/api/v1"
    name = args.name or f"smoke-{args.repo.rstrip('/').split('/')[-1].removesuffix('.git').lower()}"

    print("== health")
    wait_for_health(base)

    print("== scanners")
    print_scanners(api)

    print(f"== repository {args.repo}")
    asset_id = ensure_asset(api, name, args.repo, args.branch)

    print("== trigger scan")
    scan_id = request("POST", f"{api}/assets/{asset_id}/scan")["scan_id"]
    print(f"  scan {scan_id}")

    print("== waiting for completion")
    scan = wait_for_scan(api, scan_id)
    print(
        f"  status={scan['status']} findings={scan['total_findings']} "
        f"new={scan['new_findings']} resolved={scan['resolved_findings']} "
        f"duration={scan['duration_seconds']}s"
    )
    for execution in scan.get("executions") or []:
        line = (
            f"    {execution['scanner']:<9} {execution['status']:<9} "
            f"results={execution['result_count']:<4} {execution.get('version') or ''}"
        )
        print(line)
        if execution.get("error_message"):
            print(f"      note: {execution['error_message'][:200]}")
    if scan.get("error_message"):
        print(f"  error: {scan['error_message'][:400]}")

    dashboard = request("GET", f"{api}/dashboard/summary")
    print(
        "== dashboard "
        f"assets={dashboard['assets']['monitored']} "
        f"findings={dashboard['findings']['total']} "
        f"kev={dashboard['findings']['kev']} "
        f"intel={dashboard['intelligence']['vulnerabilities']}"
    )
    return 0 if scan["status"] == "COMPLETED" else 1


if __name__ == "__main__":
    sys.exit(main())
