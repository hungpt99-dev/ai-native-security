"""Read-only Git provider metadata client and webhook payload parsing.

Purpose: answer "what is the head commit, and which files changed since the
snapshot commit" **without cloning the repository**. That keeps the dependency
change check cheap enough to run hourly.

Nothing here writes to the database or executes a scanner. Authentication reuses
the existing encrypted repository credential (a read-only token is enough).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import quote

import httpx

from app.core.config import get_settings
from app.core.errors import AppError
from app.core.logging import get_logger
from app.core.validators import RepositoryReference

logger = get_logger(__name__)

#: Both providers cap the compare payload; hitting the cap means we cannot prove
#: the absence of dependency changes, so callers must treat it conservatively.
GITHUB_MAX_COMPARE_FILES = 300
GITLAB_MAX_COMPARE_FILES = 100


class GitProviderError(AppError):
    """The provider could not answer (network, auth, rate limit, 5xx)."""

    status_code = 502
    code = "git_provider_error"


@dataclass(frozen=True)
class CommitComparison:
    base_sha: str
    head_sha: str
    files: list[str] = field(default_factory=list)
    #: True when the provider truncated the file list; absence of dependency
    #: paths can no longer be proven.
    truncated: bool = False


@dataclass(frozen=True)
class WebhookPush:
    """Provider-neutral view of a push event."""

    repo_url: str
    branch: str
    before_sha: str | None
    after_sha: str | None
    changed_paths: list[str]
    deleted: bool = False


class RepositoryProviderClient:
    """Minimal GitHub/GitLab REST client for metadata only."""

    def __init__(self, *, timeout: float | None = None, transport: httpx.BaseTransport | None = None):
        settings = get_settings()
        self.github_api = settings.github_api_url.rstrip("/")
        self.gitlab_api = settings.gitlab_api_url.rstrip("/")
        self.timeout = timeout or settings.git_provider_timeout_seconds
        self._transport = transport

    # ------------------------------------------------------------------ plumbing
    def _get(
        self, url: str, *, provider: str, token: str | None, params: dict[str, Any] | None = None
    ) -> Any:
        headers = {"Accept": "application/json", "User-Agent": "ai-native-security/1.0"}
        if token:
            if provider == "github":
                headers["Authorization"] = f"Bearer {token}"
            else:
                headers["PRIVATE-TOKEN"] = token
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,
                transport=self._transport,
            ) as client:
                response = client.get(url, headers=headers, params=params)
        except httpx.HTTPError as exc:
            raise GitProviderError(
                "Git provider request failed", details={"url": url, "error": str(exc)[:300]}
            ) from exc
        if response.status_code in {401, 403, 404}:
            raise GitProviderError(
                "Git provider rejected the request",
                details={"url": url, "status": response.status_code},
            )
        if response.status_code >= 400:
            raise GitProviderError(
                "Git provider returned an error",
                details={"url": url, "status": response.status_code},
            )
        try:
            return response.json()
        except ValueError as exc:
            raise GitProviderError(
                "Git provider returned invalid JSON", details={"url": url}
            ) from exc

    def _repo_path(self, reference: RepositoryReference) -> str:
        return f"{reference.owner}/{reference.name}"

    # ------------------------------------------------------------------ queries
    def head_commit(
        self, reference: RepositoryReference, branch: str, *, token: str | None = None
    ) -> str:
        """Return the head commit SHA of ``branch``."""
        if reference.provider == "gitlab":
            project = quote(self._repo_path(reference), safe="")
            payload = self._get(
                f"{self.gitlab_api}/projects/{project}/repository/commits",
                provider="gitlab",
                token=token,
                params={"ref_name": branch, "per_page": 1},
            )
            if not isinstance(payload, list) or not payload:
                raise GitProviderError(
                    "GitLab returned no commits", details={"branch": branch}
                )
            sha = str(payload[0].get("id") or "")
        else:
            payload = self._get(
                f"{self.github_api}/repos/{self._repo_path(reference)}/commits/{quote(branch, safe='')}",
                provider="github",
                token=token,
            )
            sha = str(payload.get("sha") or "") if isinstance(payload, dict) else ""
        if not sha:
            raise GitProviderError("Git provider returned no commit SHA", details={"branch": branch})
        return sha[:64]

    def compare(
        self,
        reference: RepositoryReference,
        base_sha: str,
        head_sha: str,
        *,
        token: str | None = None,
    ) -> CommitComparison:
        """List changed file paths between two commits."""
        if reference.provider == "gitlab":
            project = quote(self._repo_path(reference), safe="")
            payload = self._get(
                f"{self.gitlab_api}/projects/{project}/repository/compare",
                provider="gitlab",
                token=token,
                params={"from": base_sha, "to": head_sha},
            )
            if not isinstance(payload, dict):
                raise GitProviderError("GitLab compare returned an unexpected payload")
            diffs = payload.get("diffs") or []
            paths: set[str] = set()
            for entry in diffs:
                if not isinstance(entry, dict):
                    continue
                for key in ("new_path", "old_path"):
                    value = entry.get(key)
                    if value:
                        paths.add(str(value))
            truncated = bool(payload.get("compare_timeout")) or (
                len(diffs) >= GITLAB_MAX_COMPARE_FILES
            )
            return CommitComparison(
                base_sha=base_sha,
                head_sha=head_sha,
                files=sorted(paths),
                truncated=truncated,
            )

        payload = self._get(
            f"{self.github_api}/repos/{self._repo_path(reference)}/compare/{base_sha}...{head_sha}",
            provider="github",
            token=token,
        )
        if not isinstance(payload, dict):
            raise GitProviderError("GitHub compare returned an unexpected payload")
        files = payload.get("files") or []
        paths = {
            str(entry.get("filename"))
            for entry in files
            if isinstance(entry, dict) and entry.get("filename")
        }
        truncated = bool(payload.get("truncated")) or len(files) >= GITHUB_MAX_COMPARE_FILES
        return CommitComparison(
            base_sha=base_sha,
            head_sha=head_sha,
            files=sorted(paths),
            truncated=truncated,
        )


# --------------------------------------------------------------------- webhooks
def _paths_from_commits(commits: Any) -> list[str]:
    paths: set[str] = set()
    if not isinstance(commits, list):
        return []
    for commit in commits:
        if not isinstance(commit, dict):
            continue
        for key in ("added", "modified", "removed"):
            values = commit.get(key) or []
            if isinstance(values, list):
                paths.update(str(value) for value in values if value)
    return sorted(paths)


def _branch_from_ref(ref: str | None) -> str | None:
    if not ref:
        return None
    value = str(ref)
    for prefix in ("refs/heads/", "refs/tags/"):
        if value.startswith(prefix):
            return value[len(prefix) :]
    return None


def _zero_sha(value: str | None) -> bool:
    return bool(value) and set(str(value)) == {"0"}


def parse_github_push(payload: dict[str, Any]) -> WebhookPush | None:
    """Parse a GitHub ``push`` payload. Returns ``None`` for unsupported events."""
    if (payload.get("ref") or "").startswith("refs/tags/"):
        return None
    repository = payload.get("repository") or {}
    repo_url = repository.get("clone_url") or repository.get("html_url") or ""
    branch = _branch_from_ref(payload.get("ref"))
    after = payload.get("after")
    before = payload.get("before")
    deleted = bool(payload.get("deleted")) or _zero_sha(after)
    if not repo_url or not branch:
        return None
    return WebhookPush(
        repo_url=str(repo_url),
        branch=branch,
        before_sha=str(before)[:64] if before and not _zero_sha(before) else None,
        after_sha=str(after)[:64] if after and not _zero_sha(after) else None,
        changed_paths=_paths_from_commits(payload.get("commits")),
        deleted=deleted,
    )


def parse_gitlab_push(payload: dict[str, Any]) -> WebhookPush | None:
    project = payload.get("project") or {}
    repo_url = project.get("git_http_url") or project.get("web_url") or ""
    branch = _branch_from_ref(payload.get("ref"))
    after = payload.get("after")
    before = payload.get("before")
    deleted = _zero_sha(after)
    if not repo_url or not branch:
        return None
    return WebhookPush(
        repo_url=str(repo_url),
        branch=branch,
        before_sha=str(before)[:64] if before and not _zero_sha(before) else None,
        after_sha=str(after)[:64] if after and not _zero_sha(after) else None,
        changed_paths=_paths_from_commits(payload.get("commits")),
        deleted=deleted,
    )


def payload_digest(raw_body: bytes) -> str:
    return hashlib.sha256(raw_body).hexdigest()


def parse_timestamp(value: Any) -> datetime | None:
    """Parse an RFC3339 timestamp; returns ``None`` instead of guessing."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
