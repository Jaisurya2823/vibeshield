from __future__ import annotations


def verify_evidence(file_content: str, evidence: str) -> bool:
    if not evidence:
        return False
    evidence_text = evidence.strip().lower()
    file_text = file_content.lower()
    return evidence_text in file_text