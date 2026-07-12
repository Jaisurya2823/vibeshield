from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _fingerprint(vuln) -> str:
    raw = f"{vuln.rel_path}|{vuln.category}|{vuln.evidence.strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def load_baseline(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return set(data.get("accepted_fingerprints", []))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return set()


def save_baseline(path: Path, vulnerabilities) -> None:
    fingerprints = sorted({_fingerprint(v) for v in vulnerabilities})
    data = {"version": 1, "accepted_fingerprints": fingerprints}
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def split_by_baseline(vulnerabilities, accepted_fingerprints: set[str]):
    new_findings = []
    suppressed = []
    for v in vulnerabilities:
        if _fingerprint(v) in accepted_fingerprints:
            suppressed.append(v)
        else:
            new_findings.append(v)
    return new_findings, suppressed
