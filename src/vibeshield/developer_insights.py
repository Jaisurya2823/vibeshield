from __future__ import annotations

from .state import GraphState


def build_developer_recommendations(state: GraphState) -> list[str]:
    recommendations: list[str] = []
    files = {file.rel_path.lower(): file.content.lower() for file in state.files}

    if "package.json" in files or any("dependencies" in content for content in files.values()):
        recommendations.append("Pin dependency versions and add lockfiles to reduce supply-chain drift.")
        recommendations.append("Add automated tests and a simple CI gate for package-based projects before release.")
    if any("pytest" in content or "unittest" in content for content in files.values()):
        recommendations.append("Expand automated tests to cover high-risk paths before deployment.")
    if any("dockerfile" in rel for rel in files):
        recommendations.append("Use a non-root container user and a pinned base image for safer deployments.")
    if not recommendations:
        recommendations.append("Keep code reviews and automated checks in the development workflow for safer releases.")
    return recommendations
