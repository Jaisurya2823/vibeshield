from __future__ import annotations

from .state import GraphState


def build_report_summary(state: GraphState) -> str:
    if not state.vulnerabilities:
        return "No critical issues found."

    critical_count = sum(1 for vuln in state.vulnerabilities if vuln.severity.lower() == "critical")
    moderate_count = sum(1 for vuln in state.vulnerabilities if vuln.severity.lower() == "moderate")
    categories = sorted({vuln.category for vuln in state.vulnerabilities})
    risk_level = "critical" if critical_count >= 1 else "moderate" if moderate_count else "low"
    return f"Risk level: {risk_level} — {len(state.vulnerabilities)} findings across {', '.join(categories)}."