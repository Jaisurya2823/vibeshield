from __future__ import annotations

# SARIF only defines three severity levels (error/warning/note), coarser
# than VibeShield's three (critical/moderate/low) -- this is the required
# mapping, not a design choice.
_SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "moderate": "warning",
    "low": "note",
}

_SCHEMA_URL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"


def build_sarif(state, tool_version: str = "0.2.0") -> dict:
    """
    Builds a SARIF 2.1.0 document from a completed scan's vulnerabilities.
    Rules (one per category) and results (one per finding) are separated,
    per the SARIF spec -- rules describe what CAN be found, results are
    what WAS found this run.
    """
    categories_seen: dict[str, dict] = {}
    results = []

    for vuln in state.vulnerabilities:
        if vuln.category not in categories_seen:
            categories_seen[vuln.category] = {
                "id": vuln.category,
                "name": vuln.category,
                "shortDescription": {"text": f"Potential {vuln.category.replace('_', ' ')} pattern"},
                "fullDescription": {"text": vuln.remediation.split("\n\n")[0] if vuln.remediation else vuln.category},
                "help": {"text": vuln.remediation or "No remediation guidance available."},
                "properties": {"security-severity": _security_severity_score(vuln.severity)},
            }

        results.append({
            "ruleId": vuln.category,
            "level": _SEVERITY_TO_SARIF_LEVEL.get(vuln.severity, "warning"),
            "message": {"text": f"{vuln.summary} Evidence: {vuln.evidence}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": vuln.rel_path},
                    "region": {"startLine": vuln.line if vuln.line else 1},
                }
            }],
            # GitHub uses this to track "is this the same alert as last scan"
            # across commits even if the line number shifts slightly.
            "partialFingerprints": {
                "vibeshieldEvidenceHash": _stable_hash(vuln.rel_path, vuln.category, vuln.evidence),
            },
        })

    return {
        "$schema": _SCHEMA_URL,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "vibeshield",
                    "version": tool_version,
                    "informationUri": "https://github.com/Jaisurya2823/vibeshield",
                    "rules": list(categories_seen.values()),
                }
            },
            "results": results,
        }],
    }


def _security_severity_score(severity: str) -> str:
    # GitHub reads this numeric string (0.0-10.0, CVSS-like scale) to sort
    # and badge alerts by severity in the Security tab UI.
    return {"critical": "9.0", "moderate": "5.0", "low": "2.0"}.get(severity, "5.0")


def _stable_hash(*parts: str) -> str:
    import hashlib
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]