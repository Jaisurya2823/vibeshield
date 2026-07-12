# vibeshield

Defensive-only CLI security scanner purpose-built for AI-generated
("vibe coded") web app and API source code. Finds where user input enters a
codebase, detects concrete vulnerability patterns, and gives a plain-language
risk explanation plus a concrete fix for each finding.

**Hard constraint**: detection, explanation, and remediation guidance only.
Never generates exploit code, attack payloads, or offensive/pentesting
tooling, regardless of how a request is framed.

---

## Why this exists

AI coding assistants make it easy to ship working code without fully
understanding every security implication of what got generated. vibeshield
is a safety net for that specific failure mode — point it at a folder,
get back the vulnerabilities a human reviewer would flag, in plain English,
with the actual fix.

Every claim in this README is backed by a real test, run against real code
(not just synthetic fixtures) — see [Hardening history](#hardening-history-found-fixed-and-locked-in)
below for the specific bugs this caught in its own development.

---

## Setup

```powershell
cd vibeshield
uv venv
uv pip install -e .
copy .env.example .env   # then edit .env and add your real GROQ_API_KEY
```

`GROQ_API_KEY` is optional. All 14 detection categories work with zero API
calls. A key only adds LLM-inferred risk surfaces (entry points regex can't
express — message queues, webhooks, custom parsers) and context-specific
remediation on top of the static results.

---

## Running it

```powershell
vibeshield <path-to-a-folder>
vibeshield <path-to-a-folder> --offline           # force zero API calls even if a key is set
vibeshield <path-to-a-folder> --update-baseline   # accept current findings, only report new ones from now on
vibeshield <path-to-a-folder> --no-baseline       # ignore any existing baseline, show everything
```

---

## Architecture — 4-node pipeline

```
scan_repository -> classify_risk_surface -> deep_vulnerability_read -> explain_remediate
```

| Node | File | What it does |
|---|---|---|
| Scan Repo | `src/vibeshield/nodes/scan_repo.py` | Walks the target folder, skips `.git`/`__pycache__`/`.venv`/`node_modules`/binaries/archives, reads every file. Survives permission-denied files, broken symlinks, and files removed mid-scan without crashing — reports them instead. |
| Classify Risk Surface | `src/vibeshield/nodes/classify_risk_surface.py` | Finds where user input enters the system. Regex rules -> `confirmed`. Real Groq call proposes more -> `inferred` only if evidence is verified against the actual file, else `inferred-unverified`. Entry-point labels are normalized in code against a fixed vocabulary, not left to whatever wording the model returns. |
| Deep Vulnerability Read | `src/vibeshield/nodes/deep_vulnerability_read.py` | Deterministic regex detectors across all 14 categories below. No LLM involved in this node at all. Comment/docstring content is masked before matching so prose describing a vulnerable pattern can't be mistaken for the pattern itself. |
| Explain + Remediate | `src/vibeshield/nodes/explain_remediate.py` | Static remediation template for every finding (always present). Real Groq call adds context-specific suggestion on top, when enabled. |

Supporting modules:
- `state.py` — data model (`FileRecord`, `RiskSurface`, `Vulnerability`, `GraphState`)
- `file_reader.py` — reads files with correct encoding detection (UTF-8, UTF-16, UTF-8-BOM), not a hardcoded UTF-8 assumption
- `comment_masking.py` — masks Python docstring content before regex matching to prevent false positives from prose
- `baseline.py` — accept-once suppression system so re-scans only surface genuinely new findings
- `hallucination_filter.py` — `verify_evidence()`, checks an LLM-claimed snippet actually exists in the real file content
- `secret_redaction.py` — `redact_text()`, strips secret-shaped strings before anything is sent to Groq
- `groq_client.py` — real Groq API wrapper with retry/backoff on transient failures (rate limits, timeouts); `enabled` is `True` only when a key is present AND not in offline mode; records the real failure reason instead of silently returning `None` with no explanation
- `graph.py` — wires the 4 nodes in sequence
- `cli.py` — entry point, loads `.env`, prints the report, surfaces every failure mode (truncated files, unreadable files, LLM errors) instead of a silent "clean" result
- `reporting.py`, `developer_insights.py` — report summary + guidance text

---

## Detection categories (14, multi-language)

| Category | Severity | What it catches | Languages covered |
|---|---|---|---|
| `sql_injection` | critical | String-concatenated SQL queries, including strings with a nested quote of the other type | language-agnostic pattern |
| `nosql_injection` | critical | Unvalidated request data passed into a query filter | JS/Node |
| `hardcoded_secret` | critical | API keys, passwords hardcoded in source. **Never sent to the LLM, even redacted** | language-agnostic pattern |
| `weak_hash` | moderate | MD5/SHA-1 used for hashing | Python, JS/Node, PHP, Go, Java |
| `xss` | critical | HTML built by string concat, `innerHTML =`, Go's `template.HTML()` auto-escape bypass | Python, JS/Node, Go |
| `code_injection` | critical | `eval()`/`new Function()` on unvalidated request input — arbitrary code execution, not just a shell command | JS/Node, PHP |
| `insecure_cors` | moderate | Wildcard `Access-Control-Allow-Origin` (handles both `KEY = val` and `dict['KEY'] = val` styles) | language-agnostic pattern |
| `command_injection` | critical | Shell exec with variable input | Python, JS/Node, PHP, Go, Java |
| `insecure_session` | moderate | Cookie/session security flags disabled | Python (Flask/Django), JS/Node (Express) |
| `error_disclosure` | moderate | Raw exception/stack trace returned to the client | Python, JS/Node, Go |
| `risky_dependency` | low | Unpinned dependency versions (`*`, `latest`) in the manifest. Lockfiles are excluded from this check — their `*` entries are normal peerDependency metadata, not unpinned installs | `package.json` |
| `dockerfile_root` | low | Base image pinned to `:latest` | Dockerfile |
| `insecure_auth` | critical | TLS verification disabled, JWT `algorithm="none"` | Python, Go |
| `debug_mode_enabled` | moderate | Framework debug mode left on | Python |

Every finding carries: `category`, `severity`, `confidence`
(`confirmed`/`inferred`/`inferred-unverified`), `line`, `evidence` (exact
matched text), `remediation`.

**Known remaining gaps** (named honestly, not hidden): Ruby has no dedicated
patterns in any category yet. `nosql_injection`, `insecure_session`,
`error_disclosure`, `insecure_auth`, `debug_mode_enabled` are not yet covered
for PHP/Go/Java beyond what's listed above. Comment/docstring masking only
covers Python triple-quoted strings — single-line `#`/`//` comments and
block `/* */` comments in other languages aren't masked yet, so prose in
those comment styles can still trigger a false positive the same way Python
docstrings used to. `hardcoded_secret` can miss secret values containing
non-ASCII characters.

---

## Baseline / suppression

Re-running a scanner against the same project forever re-reports the same
already-reviewed findings, which trains people to ignore the tool. The
baseline system fixes that:

```powershell
vibeshield <path> --update-baseline   # accept everything currently found
vibeshield <path>                     # only shows NEW findings from now on
vibeshield <path> --no-baseline       # see everything again, ignoring the baseline
```

Findings are matched by file + category + exact evidence text, not line
number — so unrelated edits elsewhere in a file don't cause an already-accepted
finding to reappear as "new." A corrupt or unreadable baseline file fails
safe (treated as empty, everything shown) rather than crashing the scan.

---

## Privacy / data handling

- **Zero external calls by default.** All 14 categories are fully detectable
  via local regex alone, with no `GROQ_API_KEY` set.
- **`--offline` forces this** even if a key IS present.
- **Redaction runs on every LLM call, unconditionally** (`secret_redaction.py`)
  — not a flag, not opt-in.
- **`hardcoded_secret` findings never reach the LLM at all**, redacted or
  not — locked in by `tests/test_privacy.py::test_hardcoded_secret_never_reaches_llm`.
- **`.env` is loaded automatically** by `cli.py` via `python-dotenv`.
- **Never commit a real API key.** If one is ever accidentally exposed
  (e.g. pasted somewhere), rotate it immediately at
  https://console.groq.com/keys.

---

## Testing

**Automated (48 tests):**
```powershell
uv run pytest tests/ -v
```
- `tests/test_detection_accuracy.py` — one test per category (including
  negative controls: a safe `eval('1+1')` must NOT be flagged, a Dockerfile
  version string with `+` must NOT be flagged as SQL injection), a clean-file
  negative control, and a case-insensitive-extension regression test
- `tests/test_privacy.py` — redaction, offline gating, hardcoded_secret exclusion
- `tests/test_developer_insights.py` — report summary/recommendations, and
  a permission-denied-file simulation proving one bad file can't crash the scan
- `tests/test_file_encoding.py` — UTF-16, UTF-8-with-BOM, and plain UTF-8
  files are all correctly scanned (this locks in the most severe bug found
  during hardening — see below)
- `tests/test_groq_retry.py` — transient API failures (rate limits, timeouts)
  are retried and recover; permanent failures (bad key) fail fast without
  wasting retries
- `tests/test_baseline.py` — accepted findings are suppressed on rescan, a
  genuinely new finding still surfaces even with a baseline in place, and a
  corrupt baseline file fails safe instead of crashing

**Real API call, standalone (no pytest, no mock):**
```powershell
uv run python test_real_groq_call.py
```
Confirms `GROQ_API_KEY` is actually loaded and a live Groq response comes
back — proves there's no mock path left anywhere in `groq_client.py`.

---

## Hardening history (found, fixed, and locked in)

This tool was adversarially tested against its own source, a real Node/React
project (FlowForge), and a real Python/LangGraph project (VerdictAI) — not
just curated test fixtures. Every issue below was found on real code, fixed,
and is now covered by a permanent regression test.

**The most severe finding:** reading a UTF-16-encoded file with the UTF-8
codec does not raise an error — every ASCII byte and null byte is
independently valid UTF-8 — so it silently decodes into garbage (a null byte
between every character) and every regex match breaks with zero warning.
This produces a false "clean scan" result. This is not a hypothetical edge
case: Windows PowerShell's `>` redirection and several common Windows text
editors default to UTF-16LE, making this an entirely ordinary real-world
file. Fixed by BOM-sniffing before decode; verified on a real UTF-16 file
created via `Out-File -Encoding unicode` on an actual Windows machine.

**Other real bugs found and fixed:**
- CLI argument-order parser bug (`vibeshield <path> --offline` failed, `vibeshield --offline <path>` worked) — Typer's implicit command-group behavior was reserving a `COMMAND` slot; fixed by using a single registered command instead of a bare callback.
- Files over the read-size cap were silently truncated with no indication a vulnerability past the cutoff could have been missed — now warned explicitly, and the cap was raised substantially.
- `sql_injection` regex failed on the single most common real-world shape of the vulnerability: a query string containing a nested quote of the other type (e.g. a Python double-quoted string with a SQL single-quoted value) — missed even in this project's own test fixture until fixed.
- Binary archives (`.zip`, `.tar`, etc.) were being read and scanned as text, producing wasted work and a risk of coincidental garbage matches.
- Lockfiles (`package-lock.json`, `npm-shrinkwrap.json`) were flagged for `risky_dependency` on their `peerDependencies` entries — normal, expected metadata, not a real unpinned-dependency risk. Verified via a real before/after scan of FlowForge: 6 false positives and 2 scanned archive files disappeared, exactly as predicted.
- Prose in Python docstrings describing a vulnerable pattern (e.g. a comment explaining what NOT to do) was itself triggering a false positive, because regex matching had zero awareness of comments vs. code.
- The docstring-masking fix above only checked `.endswith(".py")` case-sensitively, so an uppercase `.PY` extension reintroduced the exact same false positive it had just fixed.
- One permission-denied, deleted, or otherwise unreadable file anywhere in a scan would crash the entire run instead of being skipped and reported.
- Groq API calls had no retry logic: a single transient rate-limit or timeout partway through a scan silently degraded the rest of the run to offline-only results, with a report that looked identical to "LLM was never enabled." Now retries transient errors with backoff and records the real failure reason so the CLI can warn instead of staying silent.
- `code_injection` (the `eval()`-on-user-input detector) had zero test coverage despite being a real, documented detection category.
- `LICENSE` file was empty despite `pyproject.toml` declaring MIT, and the package version was inconsistent between `pyproject.toml` and `__init__.py`.

---

## License

MIT — see `LICENSE`.