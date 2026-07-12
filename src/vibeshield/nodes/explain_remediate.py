from __future__ import annotations

from ..groq_client import GroqClient
from ..state import GraphState

STATIC_REMEDIATION = {
    "sql_injection": "Use parameterized queries and validate all input before database access.",
    "hardcoded_secret": "Move credentials to environment variables or a secret manager and rotate exposed secrets.",
    "weak_hash": "Replace MD5/SHA-1 with a strong password hashing algorithm such as Argon2 or bcrypt.",
    "xss": "Escape or encode untrusted output and avoid rendering raw HTML.",
    "insecure_cors": "Restrict CORS origins to trusted domains and avoid wildcard access.",
    "command_injection": "Avoid shell commands built from user input; use safe APIs (e.g. subprocess with a list, shell=False).",
    "code_injection": "Never pass user input to eval() or new Function() -- this executes arbitrary code, not just arbitrary data. Use JSON.parse() for parsing structured data, or explicit type conversion (Number(), parseInt()) for numeric input.",
    "risky_dependency": "Pin dependency versions to an exact number and commit a lockfile.",
    "dockerfile_root": "Pin the base image to a specific version tag instead of :latest, and add a non-root USER.",
    "nosql_injection": "Never pass a raw request body/query object directly into a query filter. Whitelist expected fields and cast their types explicitly before using them in a query.",
    "insecure_session": "Set SESSION_COOKIE_SECURE=True and SESSION_COOKIE_HTTPONLY=True (or the equivalent for your framework) so cookies aren't sent over plain HTTP or readable by client-side JS.",
    "error_disclosure": "Never return a raw exception, its string form, or its stack trace to the client. Log full details server-side and return a generic error message instead.",
    "insecure_auth": "Never disable TLS certificate verification (verify=False) on outbound requests, and never allow the 'none' JWT algorithm -- always require a signed algorithm (HS256/RS256) and verify the signature.",
    "debug_mode_enabled": "Turn off debug mode in production (DEBUG=False). Debug mode exposes an interactive debugger and stack traces to anyone who can reach the app.",
}

LLM_EXCLUDED_CATEGORIES = {"hardcoded_secret"}

LLM_REMEDIATE_SYSTEM_PROMPT = """You are a defensive security remediation assistant.
Given a vulnerability finding and a snippet of surrounding code, write a short,
concrete remediation: what to change, with a brief corrected code example if
useful. You NEVER produce exploit code, attack payloads, or offensive tooling --
only the defensive fix. Respond with ONLY a JSON object:
{"remediation": "<2-4 sentences, concrete and specific to this code>"}
"""


def _file_context(files, rel_path: str, line: int | None, radius: int = 5) -> str:
    for f in files:
        if f.rel_path == rel_path:
            if line is None:
                return f.content[:1500]
            lines = f.content.splitlines()
            start = max(0, line - 1 - radius)
            end = min(len(lines), line + radius)
            return "\n".join(lines[start:end])
    return ""


def explain_remediate(state: GraphState) -> GraphState:
    if not state.vulnerabilities:
        state.findings.append("No vulnerabilities detected")
        return state

    client = GroqClient()
    enriched_count = 0

    for vuln in state.vulnerabilities:
        static_fix = STATIC_REMEDIATION.get(
            vuln.category, "Review the affected code path and apply a least-privilege fix."
        )
        vuln.remediation = static_fix

        if client.enabled and vuln.category not in LLM_EXCLUDED_CATEGORIES:
            context = _file_context(state.files, vuln.rel_path, vuln.line)
            if context.strip():
                result = client.analyze_json(
                    LLM_REMEDIATE_SYSTEM_PROMPT,
                    f"Category: {vuln.category}\nSeverity: {vuln.severity}\n"
                    f"File: {vuln.rel_path}\nEvidence: {vuln.evidence}\n\n"
                    f"Surrounding code:\n{context}",
                )
                if result and isinstance(result, dict) and result.get("remediation"):
                    vuln.remediation = f"{static_fix}\n\nContext-specific suggestion: {result['remediation']}"
                    enriched_count += 1

    if client.enabled:
        state.findings.append(
            f"Enriched {enriched_count}/{len(state.vulnerabilities)} remediations with LLM context "
            f"({len(LLM_EXCLUDED_CATEGORIES)} categor{'y' if len(LLM_EXCLUDED_CATEGORIES) == 1 else 'ies'} "
            f"always excluded from LLM: {', '.join(sorted(LLM_EXCLUDED_CATEGORIES))})"
        )
        if client.last_error and not state.llm_error:
            state.llm_error = client.last_error
    else:
        state.findings.append("Remediation generated from static templates only (no LLM call made)")

    return state
