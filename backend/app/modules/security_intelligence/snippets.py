"""Bounded source-snippet capture.

The scan workspace is deleted when the pipeline finishes, so any analysis that
happens later (investigation, remediation) would have no source evidence. This
step captures *only* the lines around a finding's location, redacted and capped,
into the finding metadata.

It is intentionally narrow: no whole files, no directory traversal, no binary
content, and never for findings that already carry scanner-provided lines.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import redact_text
from app.modules.findings.models import Finding
from app.modules.findings.service import anchor_metadata

logger = get_logger(__name__)

MAX_FILE_BYTES = 512 * 1024


def capture_for_scan(db: Session, *, scan_id: uuid.UUID, workspace: Path | None) -> int:
    settings = get_settings()
    if not settings.capture_code_snippets or workspace is None:
        return 0
    root = workspace.resolve()
    if not root.exists():
        return 0

    rows = (
        db.execute(
            select(Finding).where(
                Finding.last_scan_id == scan_id,
                Finding.file_path.is_not(None),
            )
        )
        .scalars()
        .all()
    )

    captured = 0
    for finding in rows:
        if finding.metadata_json and isinstance(finding.metadata_json.get("code"), dict):
            continue
        if finding.metadata_json and finding.metadata_json.get("lines"):
            continue  # scanner already supplied the matched lines
        if captured >= settings.max_snippet_files:
            break
        if not finding.file_path:
            continue
        snippet = _read_snippet(root, finding.file_path, finding.line_number, settings.max_snippet_lines)
        if snippet is None:
            continue
        anchor_metadata(finding, "code", snippet)
        captured += 1

    if captured:
        db.flush()
        logger.info(
            "code snippets captured",
            extra={"extra_fields": {"scan_id": str(scan_id), "captured": captured}},
        )
    return captured


def _read_snippet(
    root: Path, relative_path: str, line_number: int | None, max_lines: int
) -> dict[str, object] | None:
    candidate = (root / relative_path).resolve()
    if root not in candidate.parents or not candidate.is_file():
        return None
    try:
        if candidate.stat().st_size > MAX_FILE_BYTES:
            return None
        raw = candidate.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None  # binary
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if not lines:
        return None
    centre = (line_number or 1) - 1
    centre = max(0, min(centre, len(lines) - 1))
    half = max(1, max_lines // 2)
    start = max(0, centre - half)
    end = min(len(lines), centre + half)
    excerpt = "\n".join(lines[start:end])
    redacted = redact_text(excerpt)
    return {
        "text": redacted[:8000],
        "locator": f"{relative_path}:{centre + 1}",
        "start_line": start + 1,
        "end_line": end,
        "redacted": redacted != excerpt,
        "truncated": len(redacted) > 8000,
    }
