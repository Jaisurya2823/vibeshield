from __future__ import annotations

import re
from typing import Pattern

SECRET_PATTERNS: list[tuple[str, Pattern[str]]] = [
    ("Generic Secret Assignment", re.compile(r"(?i)\b(?:api[_-]?key|token|password|secret|passwd)\b\s*=\s*['\"][^'\"]+['\"]")),
    ("Generic Bearer/Secret Assignment", re.compile(r"(?i)\b(?:sk-[A-Za-z0-9]+|ghp_[A-Za-z0-9]+|AIza[0-9A-Za-z\-_]+)\b")),
    ("Private Key Block", re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----", re.S)),
]


def redact_text(text: str) -> str:
    redacted = text
    for label, pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda m: f"[REDACTED:{label}]", redacted)
    return redacted