"""Input validation helpers, most importantly repository URL validation.

Only https URLs on an allow-listed set of git hosts are accepted. This blocks
``file://``, ``ssh://``, ``git://``, local paths, host-header tricks and URL
credentials before any clone is attempted, which is the primary defence
against unexpected local file access from the worker.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from app.core.config import get_settings
from app.core.errors import ValidationError

_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")


@dataclass(frozen=True)
class RepositoryReference:
    url: str
    provider: str
    host: str
    owner: str
    name: str


def validate_repository_url(raw_url: str) -> RepositoryReference:
    """Validate and normalize a repository URL, returning its metadata."""
    settings = get_settings()
    candidate = (raw_url or "").strip()
    if not candidate:
        raise ValidationError("Repository URL is required")

    parts = urlsplit(candidate)
    if parts.scheme != "https":
        raise ValidationError(
            "Only https:// repository URLs are allowed",
            details={"scheme": parts.scheme or None, "allowed": ["https"]},
        )
    if parts.username or parts.password:
        raise ValidationError("Repository URL must not embed credentials; use a credential instead")
    if not parts.hostname:
        raise ValidationError("Repository URL must include a host")

    host = parts.hostname.lower()
    allowed_hosts = {h.lower() for h in settings.allowed_git_hosts}
    if host not in allowed_hosts:
        raise ValidationError(
            "Repository host is not allowed",
            details={"host": host, "allowed": sorted(allowed_hosts)},
        )
    # Defence in depth: an allow-listed hostname must also not resolve to a
    # literal private address (allow-lists are hostnames, not IPs).
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local):
        raise ValidationError("Repository host must not be a private address")

    path = parts.path.rstrip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    relative = path.lstrip("/")
    segments = relative.split("/")
    if len(segments) < 2 or any(not segment for segment in segments):
        raise ValidationError(
            "Repository URL must look like https://<host>/<owner>/<repo>",
            details={"path": path},
        )
    if any(segment in {".", ".."} or not _SEGMENT_RE.match(segment) for segment in segments):
        raise ValidationError(
            "Repository URL must look like https://<host>/<owner>/<repo>",
            details={"path": path},
        )
    # GitLab supports nested namespaces: keep everything before the repo name.
    owner, name = "/".join(segments[:-1]), segments[-1]

    provider = "gitlab" if "gitlab" in host else "github"
    normalized = urlunsplit(("https", host, f"/{relative}", "", ""))
    return RepositoryReference(
        url=normalized,
        provider=provider,
        host=host,
        owner=owner,
        name=name,
    )


def validate_branch_name(branch: str) -> str:
    """Reject branch names that could be parsed as git options or paths."""
    value = (branch or "").strip()
    if not value:
        raise ValidationError("Branch must not be empty")
    if value.startswith("-") or ".." in value or value.endswith(".lock"):
        raise ValidationError("Invalid branch name")
    if not re.match(r"^[A-Za-z0-9._/\-]+$", value):
        raise ValidationError("Branch name contains unsupported characters")
    if "//" in value or value.startswith("/") or value.endswith("/"):
        raise ValidationError("Invalid branch name")
    return value


def validate_authorization_header(value: str) -> str:
    """Validate a free-form ``Authorization`` style credential value."""
    candidate = (value or "").strip()
    if any(ch in candidate for ch in "\r\n\x00"):
        raise ValidationError("Credential contains invalid characters")
    if len(candidate) > 2048:
        raise ValidationError("Credential is too long")
    return candidate
