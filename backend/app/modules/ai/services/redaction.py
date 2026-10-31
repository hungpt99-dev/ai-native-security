"""Evidence sanitisation and prompt-injection detection.

Everything that comes from a scanned repository, a scanner report or a
vulnerability feed is attacker-influenced text. It is redacted before it can
reach a prompt, and scanned for instruction-like patterns so an operator can see
that an attempt was made.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from app.core.security import redact_text

#: Patterns that indicate an attempt to issue instructions to the model. They are
#: recorded as evidence attributes; the system prompt already states that
#: evidence is data, so detection is for visibility, not the only defence.
INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ignore_instructions",
        re.compile(
            r"\b(ignore|disregard|forget)\b[^\n]{0,40}\b(previous|prior|above|earlier)\b[^\n]{0,20}\b(instructions?|prompts?|rules?)\b",
            re.I,
        ),
    ),
    (
        "role_override",
        re.compile(r"\byou are (now|no longer)\b|\bact as\b[^\n]{0,30}\b(admin|root|system)\b", re.I),
    ),
    (
        "system_prompt_exfil",
        re.compile(r"\b(reveal|print|show|repeat)\b[^\n]{0,30}\b(system prompt|instructions)\b", re.I),
    ),
    (
        "verdict_injection",
        re.compile(
            r"\b(mark|classify|report|consider)\b[^\n]{0,40}"
            r"\b(false positive|as safe|not exploitable|resolved|benign)\b",
            re.I,
        ),
    ),
    ("tool_request", re.compile(r"\b(run|execute)\b[^\n]{0,20}\b(command|shell|curl|wget|bash)\b", re.I)),
    ("jailbreak", re.compile(r"\b(jailbreak|developer mode|do anything now|DAN mode)\b", re.I)),
)


@dataclass
class SanitizedText:
    text: str
    redacted: bool = False
    truncated: bool = False
    injection_markers: list[str] = field(default_factory=list)
    sha256: str = ""

    @property
    def safe_to_send(self) -> bool:
        return bool(self.text.strip())


def detect_injection(text: str) -> list[str]:
    if not text:
        return []
    markers: list[str] = []
    for name, pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            markers.append(name)
    return markers


def sanitize(text: str | None, *, max_chars: int = 4000) -> SanitizedText:
    """Redact secret-shaped strings, cap length, hash the result.

    The hash is computed over the sanitized text, so it matches what a reader of
    the stored evidence would see and can be compared across runs.
    """
    if not text:
        return SanitizedText(text="", sha256=hashlib.sha256(b"").hexdigest())
    original = text
    redacted_text = redact_text(original)
    truncated = False
    if len(redacted_text) > max_chars:
        redacted_text = redacted_text[:max_chars] + "\n[truncated]"
        truncated = True
    return SanitizedText(
        text=redacted_text,
        redacted=redacted_text != original,
        truncated=truncated,
        injection_markers=detect_injection(original),
        sha256=hashlib.sha256(redacted_text.encode()).hexdigest(),
    )
