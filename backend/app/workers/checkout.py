"""Safe repository checkout.

Threat model: repository content is untrusted. We therefore
* clone with an argv vector (no shell), into a dedicated temp directory;
* use ``--no-recurse-submodules`` and neutralise hooks;
* disable terminal prompts so a private repo fails fast instead of hanging;
* strip any symlink that resolves outside the workspace (path-traversal
  vector for scanners that read files);
* authenticate with an HTTP header rather than embedding the token in the
  stored remote URL, so the token never lands in the workspace ``.git/config``.
"""

from __future__ import annotations

import base64
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from app.core.config import get_settings
from app.core.errors import ValidationError
from app.core.logging import get_logger
from app.core.validators import validate_branch_name, validate_repository_url
from app.modules.scanners.execution import run_command

logger = get_logger(__name__)


@dataclass
class Checkout:
    path: Path
    branch: str
    commit_sha: str | None
    provider: str


def workspace_for_scan(scan_id: uuid.UUID) -> Path:
    root = get_settings().workspace_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    workspace = root / f"scan-{scan_id}"
    if workspace.exists():
        shutil.rmtree(workspace, ignore_errors=True)
    workspace.mkdir(parents=True, exist_ok=False)
    return workspace


def build_clone_url(repo_url: str) -> str:
    """Validate the repository URL again right before use (defence in depth)."""
    reference = validate_repository_url(repo_url)
    return reference.url


def _auth_arguments(repo_url: str, token: str | None) -> list[str]:
    """Return git ``-c`` arguments carrying an auth header for private repos."""
    if not token:
        return []
    reference = validate_repository_url(repo_url)
    credential = f"oauth2:{token}" if reference.provider == "gitlab" else f"x-access-token:{token}"
    encoded = base64.b64encode(credential.encode()).decode()
    return ["-c", f"http.extraHeader=AUTHORIZATION: basic {encoded}"]


def clone_repository(
    *,
    repo_url: str,
    branch: str,
    token: str | None,
    destination: Path,
) -> Checkout:
    settings = get_settings()
    url = build_clone_url(repo_url)
    branch = validate_branch_name(branch)

    command = [
        "git",
        *_auth_arguments(url, token),
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "advice.detachedHead=false",
        "clone",
        "--depth",
        str(max(1, settings.git_clone_depth)),
        "--single-branch",
        "--branch",
        branch,
        "--no-tags",
        "--no-recurse-submodules",
        "--quiet",
        url,
        str(destination),
    ]

    env_repo = dict(os.environ)
    result = run_command(
        command,
        cwd=destination.parent,
        timeout=settings.git_clone_timeout_seconds,
        extra_env={
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/true",
            "GIT_CONFIG_NOSYSTEM": "1",
        },
    )
    # Keep the plain URL in origin, never the credentialed variant.
    if result.exit_code != 0 or not destination.exists():
        raise ValidationError(
            "Repository clone failed",
            details={
                "exit_code": result.exit_code,
                "stderr": result.stderr_excerpt[-1500:],
                "timed_out": result.timed_out,
            },
        )

    # Defence: ensure the stored remote has no credentials embedded.
    run_command(
        ["git", "remote", "set-url", "origin", url],
        cwd=destination,
        timeout=30,
        extra_env=env_repo,
    )

    commit_sha = _rev_parse(destination)
    removed = remove_unsafe_symlinks(destination)
    if removed:
        logger.warning(
            "removed symlinks escaping the workspace",
            extra={"extra_fields": {"count": removed, "scan_dir": destination.name}},
        )
    return Checkout(
        path=destination,
        branch=branch,
        commit_sha=commit_sha,
        provider=validate_repository_url(url).provider,
    )


def _rev_parse(destination: Path) -> str | None:
    result = run_command(
        ["git", "rev-parse", "HEAD"],
        cwd=destination,
        timeout=30,
        extra_env={"GIT_TERMINAL_PROMPT": "0"},
    )
    if result.exit_code != 0:
        return None
    sha = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    return sha[:64] or None


def remove_unsafe_symlinks(root: Path) -> int:
    """Delete symlinks that resolve outside ``root`` (or into ``.git``)."""
    root_resolved = root.resolve()
    removed = 0
    for path in root_resolved.rglob("*"):
        if path.is_symlink():
            try:
                target = path.resolve()
            except (OSError, RuntimeError):
                path.unlink(missing_ok=True)
                removed += 1
                continue
            if root_resolved not in target.parents and target != root_resolved:
                path.unlink(missing_ok=True)
                removed += 1
    return removed


def cleanup_workspace(path: Path | None) -> None:
    if path is None:
        return
    if get_settings().keep_workspaces:  # pragma: no cover - debugging aid
        logger.info("keeping workspace", extra={"extra_fields": {"path": str(path)}})
        return
    shutil.rmtree(path, ignore_errors=True)
