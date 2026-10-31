"""Hardened subprocess execution for external security tools.

Security properties:
* argument vectors only (``shell=False``), so no shell interpolation or
  command injection through repository metadata;
* sanitised environment: credentials and ``ANS_*`` secrets are stripped;
* executed in a dedicated session/process group so a timeout kills the whole
  tree (``killpg``);
* ``RLIMIT_AS``/``RLIMIT_NPROC``/``RLIMIT_FSIZE`` caps where supported;
* bounded, redacted stdout/stderr excerpts.
"""

from __future__ import annotations

import contextlib
import json
import os
import resource
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import redact_text

logger = get_logger(__name__)

EXCERPT_LIMIT = 4000


@dataclass
class ProcessResult:
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False

    @property
    def stdout_excerpt(self) -> str:
        return redact_text(self.stdout[-EXCERPT_LIMIT:])

    @property
    def stderr_excerpt(self) -> str:
        return redact_text(self.stderr[-EXCERPT_LIMIT:])


def sanitized_env(home: Path | None = None) -> dict[str, str]:
    """Return a minimal environment without application secrets."""
    allowed_prefixes = ("PATH", "LANG", "LC_", "TZ", "SSL_CERT", "REQUESTS_CA", "CURL_CA")
    env = {
        key: value
        for key, value in os.environ.items()
        if key.startswith(allowed_prefixes) and not key.startswith("ANS_")
    }
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env["HOME"] = str(home or "/tmp")  # noqa: S108 - isolated HOME for scanner subprocesses
    env["PYTHONUNBUFFERED"] = "1"
    env["SEMGREP_SEND_METRICS"] = "off"
    env["TRIVY_NO_PROGRESS"] = "true"
    env["NO_COLOR"] = "1"
    # Explicitly drop anything that looks like a credential.
    for key in list(env):
        if any(token in key.upper() for token in ("TOKEN", "SECRET", "PASSWORD", "API_KEY")):
            env.pop(key, None)
    return env


def _apply_limits() -> None:  # pragma: no cover - runs in the child process
    settings = get_settings()
    os.setsid()
    memory = settings.scanner_max_memory_mb * 1024**2
    file_size = settings.scanner_max_file_size_mb * 1024**2
    processes = settings.scanner_max_processes
    try:
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_NPROC, (processes, processes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_size, file_size))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):  # not all platforms permit every limit
        pass


def run_command(
    command: list[str],
    *,
    cwd: Path,
    timeout: int | None = None,
    extra_env: dict[str, str] | None = None,
) -> ProcessResult:
    settings = get_settings()
    timeout = timeout or settings.scanner_timeout_seconds
    env = sanitized_env(home=cwd)
    if extra_env:
        env.update(extra_env)

    logger.info(
        "executing external command",
        extra={"extra_fields": {"binary": command[0], "cwd": str(cwd)}},
    )
    started = time.perf_counter()
    process = subprocess.Popen(  # noqa: S603 - argv list, no shell
        command,
        cwd=str(cwd),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=_apply_limits,
        close_fds=True,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        with contextlib.suppress(ProcessLookupError):
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        stdout, stderr = process.communicate()
        stderr = f"{stderr}\nProcess exceeded timeout of {timeout}s and was terminated"
    duration = time.perf_counter() - started
    result = ProcessResult(
        command=command,
        exit_code=process.returncode,
        stdout=stdout or "",
        stderr=stderr or "",
        duration_seconds=round(duration, 2),
        timed_out=timed_out,
    )
    logger.info(
        "external command finished",
        extra={
            "extra_fields": {
                "binary": command[0],
                "exit_code": result.exit_code,
                "duration_seconds": result.duration_seconds,
                "timed_out": timed_out,
            }
        },
    )
    return result


def binary_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def read_json_report(path: Path) -> Any:
    """Read a scanner JSON report, tolerating empty/whitespace-only files."""
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return None
    return json.loads(text)


@dataclass
class ScannerAvailability:
    available: bool
    version: str | None = None
    error: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "version": self.version,
            "error": self.error,
            "details": self.details,
        }
