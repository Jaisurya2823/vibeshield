import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vibeshield.groq_client import GroqClient
from vibeshield.secret_redaction import redact_text


class PrivacySafeguardsTests(unittest.TestCase):
    def test_redact_text_hides_secret_values(self) -> None:
        source = 'API_KEY = "sk-live-123456"\nprint(API_KEY)'
        redacted = redact_text(source)
        self.assertIn("[REDACTED:Generic Secret Assignment]", redacted)
        self.assertNotIn("sk-live-123456", redacted)

    def test_offline_mode_blocks_llm_calls(self) -> None:
        client = GroqClient(api_key="fake-key", offline=True)
        self.assertIsNone(client.analyze("hello"))
        self.assertFalse(client.enabled)

    def test_no_api_key_blocks_llm_calls(self) -> None:
        client = GroqClient(api_key=None, offline=False)
        self.assertIsNone(client.analyze("hello"))
        self.assertFalse(client.enabled)

    def test_enabled_only_when_key_present_and_not_offline(self) -> None:
        client = GroqClient(api_key="fake-key", offline=False)
        self.assertTrue(client.enabled)

    def test_hardcoded_secret_never_reaches_llm(self) -> None:
        """
        Even with a real key and LLM enabled, hardcoded_secret findings must
        never trigger an analyze_json call -- the evidence for this category
        IS the secret, and there's no reason to transmit that code path
        anywhere, even redacted.
        """
        import sys
        import tempfile
        from pathlib import Path as _Path
        from unittest.mock import patch

        sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "src"))
        from vibeshield.graph import run_graph

        with tempfile.TemporaryDirectory() as tmpdir:
            root = _Path(tmpdir)
            (root / "app.py").write_text(
                'API_KEY = "sk-live-abcdef1234567890"\n', encoding="utf-8"
            )

            with patch.dict("os.environ", {"GROQ_API_KEY": "fake-key", "VIBESHIELD_OFFLINE": "0"}):
                with patch("vibeshield.groq_client.GroqClient.analyze_json") as mock_analyze:
                    mock_analyze.return_value = {"remediation": "should never be called"}
                    state = run_graph(str(root))

                    secret_findings = [v for v in state.vulnerabilities if v.category == "hardcoded_secret"]
                    self.assertTrue(len(secret_findings) > 0, "expected a hardcoded_secret finding to test against")

                    # analyze_json may still be called for classify_risk_surface
                    # on other categories, so check no call was made *for*
                    # the hardcoded_secret vulnerability specifically by
                    # confirming its remediation is still the static template.
                    for finding in secret_findings:
                        self.assertNotIn("Context-specific suggestion", finding.remediation)


if __name__ == "__main__":
    unittest.main()