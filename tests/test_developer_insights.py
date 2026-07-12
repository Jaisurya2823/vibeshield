import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vibeshield.developer_insights import build_developer_recommendations
from vibeshield.nodes.scan_repo import scan_repository
from vibeshield.reporting import build_report_summary
from vibeshield.state import GraphState, Vulnerability


class DeveloperInsightsTests(unittest.TestCase):
    def test_scan_repository_keeps_relative_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            src_dir = root / "src"
            src_dir.mkdir()
            (src_dir / "app.py").write_text("print('ok')", encoding="utf-8")

            state = GraphState(target_path=str(root))
            state = scan_repository(state)

            self.assertTrue(any(file.rel_path == "src/app.py" for file in state.files))

    def test_build_recommendations_mentions_tests_and_pinning(self) -> None:
        state = GraphState(target_path=".")
        state.files = [
            type("FileRecord", (), {"rel_path": "package.json", "content": '{"dependencies": {"left-pad": "*"}}'})(),
        ]
        recommendations = build_developer_recommendations(state)
        combined = "\n".join(recommendations).lower()
        self.assertIn("test", combined)
        self.assertIn("pin", combined)

    def test_build_report_summary_reports_risk_level(self) -> None:
        state = GraphState(target_path=".")
        state.vulnerabilities = [
            Vulnerability(path="app.py", rel_path="app.py", category="sql_injection", severity="critical", summary="Potential sql injection", evidence="select * from", remediation="Use parameterized queries"),
            Vulnerability(path="app.py", rel_path="app.py", category="xss", severity="moderate", summary="Potential xss", evidence="render_template_string", remediation="Escape output"),
        ]
        summary = build_report_summary(state)
        self.assertIn("critical", summary.lower())
        self.assertIn("2", summary)


if __name__ == "__main__":
    unittest.main()