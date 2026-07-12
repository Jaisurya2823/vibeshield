import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vibeshield.graph import run_graph


class DetectionAccuracyTests(unittest.TestCase):
    """
    Regression test for the 'same output every run' bug: the old
    CATEGORY_RULES matched bare words like "user" and "from " that appear
    in almost any file, producing near-identical findings regardless of
    actual content. This test locks in that a clean file with those exact
    words present -- but no real vulnerable pattern -- produces zero
    vulnerabilities and zero risk surfaces.
    """

    def test_clean_file_with_generic_words_produces_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "utils.py").write_text(
                "from datetime import datetime\n"
                "import json\n\n"
                "class UserProfile:\n"
                "    def __init__(self, user_id):\n"
                "        self.user_id = user_id\n\n"
                "    def to_json(self):\n"
                "        return json.dumps({'id': self.user_id})\n",
                encoding="utf-8",
            )

            state = run_graph(str(root))

            self.assertEqual(
                len(state.vulnerabilities), 0,
                f"Expected no vulnerabilities in a clean file, got: "
                f"{[v.category for v in state.vulnerabilities]}"
            )
            self.assertEqual(
                len(state.risk_surfaces), 0,
                f"Expected no risk surfaces in a clean file, got: "
                f"{[r.entry_point for r in state.risk_surfaces]}"
            )

    def test_sql_injection_not_flagged_on_shell_command_with_unrelated_plus(self) -> None:
        """
        Regression test for a real false positive found scanning OWASP PyGoat:
        'RUN apt-get update && ... dnsutils=1:9.11.5.P4+dfsg-5.1+deb10u11' was
        flagged as sql_injection because the word "update" matched the SQL
        UPDATE keyword, and a completely unrelated '+' later in the same line
        (a Debian package version string) satisfied the concatenation check.
        The fix requires the SQL keyword to actually be inside a quoted
        string literal, which shell commands like this never are.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Dockerfile").write_text(
                "RUN apt-get update && apt-get install --no-install-recommends "
                "-y dnsutils=1:9.11.5.P4+dfsg-5.1+deb10u11\n",
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertNotIn("sql_injection", categories)

    def test_argparse_cli_argument_recognized_as_risk_surface(self) -> None:
        """
        Regression test for a real gap found scanning the user's own CLI
        tool (AI-codebase-onboarding-agent): argparse-based CLI arguments
        are genuine external input, but ENTRY_POINT_PATTERNS previously only
        recognized web-framework input (Flask/Express), so any pure CLI
        tool got zero risk surfaces regardless of real input handling.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "main.py").write_text(
                "import argparse\n"
                "parser = argparse.ArgumentParser()\n"
                "parser.add_argument('--repo', required=True)\n",
                encoding="utf-8",
            )
            state = run_graph(str(root))
            entry_points = [s.entry_point for s in state.risk_surfaces]
            self.assertIn("CLI argument (argparse)", entry_points)

    def test_real_sql_injection_is_still_caught(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text(
                "def get_user(user_id):\n"
                "    query = \"SELECT * FROM users WHERE id = \" + user_id\n"
                "    cur.execute(query)\n",
                encoding="utf-8",
            )

            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]

            self.assertIn("sql_injection", categories)

    def test_nosql_injection_is_caught(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.js").write_text(
                "function findOrders(req) {\n"
                "    return collection.find(req.body);\n"
                "}\n",
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("nosql_injection", categories)

    def test_insecure_session_cookie_is_caught(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text(
                'app.config["SESSION_COOKIE_SECURE"] = False\n',
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("insecure_session", categories)

    def test_insecure_cors_with_bracket_assignment_is_caught(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text(
                "@app.after_request\n"
                "def add_cors(response):\n"
                "    response.headers['Access-Control-Allow-Origin'] = '*'\n"
                "    return response\n",
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("insecure_cors", categories)

    def test_error_disclosure_is_caught(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text(
                "@app.errorhandler(Exception)\n"
                "def handle_error(e):\n"
                "    return str(e)\n",
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("error_disclosure", categories)

    def test_tls_verify_disabled_is_caught(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text(
                "resp = requests.get(target, verify=False)\n",
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("insecure_auth", categories)

    def test_jwt_none_algorithm_is_caught(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text(
                'token = jwt.encode(payload, key, algorithm="none")\n',
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("insecure_auth", categories)

    def test_debug_mode_enabled_is_caught(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text(
                'app.config["DEBUG"] = True\n',
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("debug_mode_enabled", categories)

    def test_weak_hash_caught_in_javascript(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.js").write_text(
                "const hash = crypto.createHash('md5').update(data).digest('hex');\n",
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("weak_hash", categories)

    def test_weak_hash_caught_in_php(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.php").write_text(
                '<?php $hash = md5($password); ?>\n',
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("weak_hash", categories)

    def test_command_injection_caught_in_javascript(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.js").write_text(
                "child_process.exec('ls ' + userInput);\n",
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("command_injection", categories)

    def test_command_injection_caught_in_php(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.php").write_text(
                '<?php exec($_GET["cmd"]); ?>\n',
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("command_injection", categories)

    def test_weak_hash_caught_in_go(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "main.go").write_text(
                "h := md5.New()\nh.Write(data)\n",
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("weak_hash", categories)

    def test_weak_hash_caught_in_java(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "App.java").write_text(
                'MessageDigest md = MessageDigest.getInstance("MD5");\n',
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("weak_hash", categories)

    def test_repeated_entry_point_pattern_gets_distinct_line_numbers(self) -> None:
        """
        Regression test for a real bug found scanning OWASP PyGoat: the line
        number lookup re-searched the file for the literal matched text
        (e.g. "@app.route(") instead of using the match's actual position,
        so every occurrence after the first was reported at the position of
        the FIRST occurrence. A file with 7 routes showed all 7 at the same
        wrong line number. This confirms 3 separate matches get 3 distinct,
        correct line numbers.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text(
                "@app.route('/a')\n"
                "def a():\n"
                "    pass\n\n"
                "@app.route('/b')\n"
                "def b():\n"
                "    pass\n\n"
                "@app.route('/c')\n"
                "def c():\n"
                "    pass\n",
                encoding="utf-8",
            )
            state = run_graph(str(root))
            route_surfaces = [s for s in state.risk_surfaces if s.entry_point == "HTTP request handler"]
            lines = sorted(s.line for s in route_surfaces)
            self.assertEqual(lines, [1, 5, 9])

    def test_command_injection_caught_in_go_with_variable_arg(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "main.go").write_text(
                "cmd := exec.Command(userInput, args...)\n",
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("command_injection", categories)

    def test_command_injection_not_flagged_in_go_with_literal_args(self) -> None:
        """A negative control: exec.Command with string-literal args is safe
        and must NOT be flagged -- the pattern targets variable-driven calls."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "main.go").write_text(
                'cmd := exec.Command("ls", "-la")\n',
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertNotIn("command_injection", categories)

    def test_command_injection_caught_in_java(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "App.java").write_text(
                "Runtime.getRuntime().exec(userCmd);\n",
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("command_injection", categories)

    def test_xss_caught_in_go_template_html_cast(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "main.go").write_text(
                "func render(w http.ResponseWriter, userInput string) {\n"
                "    fmt.Fprint(w, template.HTML(userInput))\n"
                "}\n",
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("xss", categories)

    def test_insecure_session_caught_in_express_cookie_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.js").write_text(
                "app.use(session({cookie: {secure: false}}));\n",
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("insecure_session", categories)

    def test_error_disclosure_caught_in_go(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "main.go").write_text(
                "func handler(w http.ResponseWriter, r *http.Request) {\n"
                "    if err != nil {\n"
                "        http.Error(w, err.Error(), 500)\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("error_disclosure", categories)

    def test_insecure_auth_caught_in_go_tls_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "main.go").write_text(
                'tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}\n',
                encoding="utf-8",
            )
            state = run_graph(str(root))
            categories = [v.category for v in state.vulnerabilities]
            self.assertIn("insecure_auth", categories)


if __name__ == "__main__":
    unittest.main()