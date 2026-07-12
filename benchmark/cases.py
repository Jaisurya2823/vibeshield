"""
Labeled benchmark corpus for measuring real detection accuracy.

Each case has KNOWN GROUND TRUTH: either it should trigger a specific
category (a true positive expectation), or it's a "safe but similar-looking"
counterpart that should trigger NOTHING (a true negative expectation --
this is what actually tests for false positives, not just "does the tool
find the obvious bug").

This is not a synthetic word-salad negative control (that's what
test_clean_file_with_generic_words_produces_no_findings already covers).
These safe cases are deliberately close to the vulnerable ones -- same
library, same shape, the ONE thing that differs is the fix -- because that's
what actually stresses whether the regex is precise or just pattern-matching
on library names.
"""

from dataclasses import dataclass


@dataclass
class BenchmarkCase:
    category: str          # which category this case is about
    label: str             # "vulnerable" or "safe"
    filename: str          # extension matters, affects language-specific rules
    content: str
    expect_category: bool  # True: category MUST appear in findings. False: category MUST NOT appear.


CASES: list[BenchmarkCase] = [
    # sql_injection
    BenchmarkCase("sql_injection", "vulnerable", "app.py", (
        "def get_user(user_id):\n"
        "    query = \"SELECT * FROM users WHERE id = \" + user_id\n"
        "    cur.execute(query)\n"
    ), True),
    BenchmarkCase("sql_injection", "safe", "app.py", (
        "def get_user(user_id):\n"
        "    query = \"SELECT * FROM users WHERE id = %s\"\n"
        "    cur.execute(query, (user_id,))\n"
    ), False),

    # nosql_injection
    BenchmarkCase("nosql_injection", "vulnerable", "app.js", (
        "function findOrders(req) {\n"
        "    return collection.find(req.body);\n"
        "}\n"
    ), True),
    BenchmarkCase("nosql_injection", "safe", "app.js", (
        "function findOrders(req) {\n"
        "    const id = String(req.body.id);\n"
        "    return collection.find({ id: id });\n"
        "}\n"
    ), False),

    # hardcoded_secret
    BenchmarkCase("hardcoded_secret", "vulnerable", "app.py", (
        'API_KEY = "sk-live-abcdef1234567890"\n'
    ), True),
    BenchmarkCase("hardcoded_secret", "safe", "app.py", (
        'API_KEY = os.environ.get("API_KEY")\n'
    ), False),

    # weak_hash
    BenchmarkCase("weak_hash", "vulnerable", "app.py", (
        "import hashlib\n"
        "def hash_password(p):\n"
        "    return hashlib.md5(p.encode()).hexdigest()\n"
    ), True),
    BenchmarkCase("weak_hash", "safe", "app.py", (
        "import bcrypt\n"
        "def hash_password(p):\n"
        "    return bcrypt.hashpw(p.encode(), bcrypt.gensalt())\n"
    ), False),

    # xss
    BenchmarkCase("xss", "vulnerable", "app.py", (
        "from flask import render_template_string, request\n"
        "def greet():\n"
        "    name = request.args.get('name', '')\n"
        "    return render_template_string('<h1>Hello ' + name + '</h1>')\n"
    ), True),
    BenchmarkCase("xss", "safe", "app.py", (
        "from flask import render_template, request\n"
        "def greet():\n"
        "    name = request.args.get('name', '')\n"
        "    return render_template('greet.html', name=name)\n"
    ), False),

    # insecure_cors
    BenchmarkCase("insecure_cors", "vulnerable", "app.py", (
        "@app.after_request\n"
        "def add_cors(response):\n"
        "    response.headers['Access-Control-Allow-Origin'] = '*'\n"
        "    return response\n"
    ), True),
    BenchmarkCase("insecure_cors", "safe", "app.py", (
        "@app.after_request\n"
        "def add_cors(response):\n"
        "    response.headers['Access-Control-Allow-Origin'] = 'https://example.com'\n"
        "    return response\n"
    ), False),

    # command_injection
    BenchmarkCase("command_injection", "vulnerable", "app.py", (
        "import subprocess\n"
        "def ping(host):\n"
        "    subprocess.run(host, shell=True)\n"
    ), True),
    BenchmarkCase("command_injection", "safe", "app.py", (
        "import subprocess\n"
        "def ping(host):\n"
        "    subprocess.run(['ping', '-c', '1', host], shell=False)\n"
    ), False),

    # insecure_session
    BenchmarkCase("insecure_session", "vulnerable", "app.py", (
        'app.config["SESSION_COOKIE_SECURE"] = False\n'
    ), True),
    BenchmarkCase("insecure_session", "safe", "app.py", (
        'app.config["SESSION_COOKIE_SECURE"] = True\n'
        'app.config["SESSION_COOKIE_HTTPONLY"] = True\n'
    ), False),

    # error_disclosure
    BenchmarkCase("error_disclosure", "vulnerable", "app.py", (
        "@app.errorhandler(Exception)\n"
        "def handle_error(e):\n"
        "    return str(e)\n"
    ), True),
    BenchmarkCase("error_disclosure", "safe", "app.py", (
        "@app.errorhandler(Exception)\n"
        "def handle_error(e):\n"
        "    app.logger.exception(e)\n"
        "    return 'An internal error occurred', 500\n"
    ), False),

    # risky_dependency
    BenchmarkCase("risky_dependency", "vulnerable", "package.json", (
        '{"name": "app", "dependencies": {"left-pad": "*"}}\n'
    ), True),
    BenchmarkCase("risky_dependency", "safe", "package.json", (
        '{"name": "app", "dependencies": {"left-pad": "1.3.0"}}\n'
    ), False),

    # dockerfile_root
    BenchmarkCase("dockerfile_root", "vulnerable", "Dockerfile", (
        "FROM python:latest\nCMD [\"python\", \"app.py\"]\n"
    ), True),
    BenchmarkCase("dockerfile_root", "safe", "Dockerfile", (
        "FROM python:3.12.4-slim\nUSER appuser\nCMD [\"python\", \"app.py\"]\n"
    ), False),

    # insecure_auth
    BenchmarkCase("insecure_auth", "vulnerable", "app.py", (
        "resp = requests.get(target, verify=False)\n"
    ), True),
    BenchmarkCase("insecure_auth", "safe", "app.py", (
        "resp = requests.get(target, verify=True)\n"
    ), False),

    # debug_mode_enabled
    BenchmarkCase("debug_mode_enabled", "vulnerable", "app.py", (
        'app.config["DEBUG"] = True\n'
    ), True),
    BenchmarkCase("debug_mode_enabled", "safe", "app.py", (
        'app.config["DEBUG"] = False\n'
    ), False),

    # code_injection -- found via real-world testing against OWASP NodeGoat,
    # not self-authored first; this is NodeGoat's own documented A1 lesson.
    BenchmarkCase("code_injection", "vulnerable", "app.js", (
        "const preTax = eval(req.body.preTax);\n"
    ), True),
    BenchmarkCase("code_injection", "safe", "app.js", (
        "const preTax = Number(req.body.preTax);\n"
    ), False),
]