from __future__ import annotations

from pathlib import Path

from .developer_insights import build_developer_recommendations
from .nodes.scan_repo import scan_repository
from .nodes.classify_risk_surface import classify_risk_surface
from .nodes.deep_vulnerability_read import deep_vulnerability_read
from .nodes.explain_remediate import explain_remediate
from .state import GraphState


def run_graph(target_path: str) -> GraphState:
    target = Path(target_path).resolve()
    state = GraphState(target_path=str(target))
    state = scan_repository(state)
    state = classify_risk_surface(state)
    state = deep_vulnerability_read(state)
    state = explain_remediate(state)
    state.findings.extend(build_developer_recommendations(state))
    return state