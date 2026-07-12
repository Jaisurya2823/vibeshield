from __future__ import annotations

import os
import re

from ..groq_client import GroqClient
from ..hallucination_filter import verify_evidence
from ..comment_masking import mask_python_docstrings
from ..state import GraphState, RiskSurface

ENTRY_POINT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("HTTP request handler", re.compile(r"@app\.route\(")),
    ("User input (Flask)", re.compile(r"request\.(args|form|json|values)\b")),
    ("User input (raw)", re.compile(r"\binput\s*\(")),
    ("User input (Express)", re.compile(r"req\.(query|body|params)\b")),
    ("CLI argument (argparse)", re.compile(r"argparse\.ArgumentParser\(")),
    ("CLI argument (sys.argv)", re.compile(r"sys\.argv\b")),
    ("CLI argument (click)", re.compile(r"@click\.(option|argument)\(")),
    ("Environment variable", re.compile(r"os\.(environ\b|getenv\()")),
]

LLM_ELIGIBLE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".go", ".java"}

CLASSIFY_SYSTEM_PROMPT = """You are a defensive security static-analysis assistant.
Identify where external/user-controlled input enters this code file (HTTP params,
form fields, GraphQL args, message-queue payloads, webhook bodies, WebSocket
messages, file uploads, etc) that the following pattern list may have missed:
@app.route, request.args/form/json/values, input(), req.query/body/params.

Rules, follow exactly:
1. For each distinct external input source, report exactly ONE finding: the
   single earliest line where the untrusted value is first read into a
   variable (e.g. "payload = message.value" or "data = request.get_data()").
   Do NOT report the connection/subscription/setup line (e.g. where a
   consumer or socket is created) and do NOT report a later line that merely
   uses a variable already derived from that input -- only the first read.
2. Never report the same external input source more than once, even if it
   is referenced again later in the file.
3. "entry_point" MUST be exactly one of this fixed list (pick the closest
   match, do not invent new wording): "HTTP request", "message queue",
   "webhook payload", "websocket message", "file upload", "GraphQL argument",
   "CLI input", "environment variable", "other external input".

Respond with ONLY a JSON object:
{"findings": [{"entry_point": "<one of the fixed list above>",
"rationale": "<one short sentence>",
"evidence": "<EXACT line copied verbatim from the file>"}]}

"evidence" MUST be an exact substring of the file content given -- do not
paraphrase or reconstruct it. If you cannot quote a real line verbatim, omit
that finding. If there are no additional entry points, return {"findings": []}.
"""


def _line_number_from_pos(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


ALLOWED_ENTRY_POINTS = [
    "HTTP request", "message queue", "webhook payload", "websocket message",
    "file upload", "GraphQL argument", "CLI input", "environment variable",
    "other external input",
]

_ENTRY_POINT_KEYWORDS: list[tuple[str, str]] = [
    ("kafka", "message queue"), ("rabbitmq", "message queue"), ("queue", "message queue"),
    ("sqs", "message queue"), ("pubsub", "message queue"), ("topic", "message queue"),
    ("webhook", "webhook payload"),
    ("websocket", "websocket message"), ("socket.io", "websocket message"),
    ("upload", "file upload"), ("multipart", "file upload"),
    ("graphql", "GraphQL argument"),
    ("cli", "CLI input"), ("argv", "CLI input"), ("command line", "CLI input"),
    ("environment", "environment variable"), ("env var", "environment variable"),
    ("http", "HTTP request"), ("request", "HTTP request"), ("api", "HTTP request"),
]


def _normalize_entry_point(raw: str) -> str:
    if raw in ALLOWED_ENTRY_POINTS:
        return raw
    lowered = raw.lower()
    for keyword, category in _ENTRY_POINT_KEYWORDS:
        if keyword in lowered:
            return category
    return "other external input"


def _line_number_from_snippet(content: str, snippet: str) -> int | None:
    idx = content.find(snippet)
    if idx == -1:
        return None
    return content[:idx].count("\n") + 1


def _llm_findings(file, client: GroqClient) -> list[RiskSurface]:
    _, ext = os.path.splitext(file.rel_path)
    if ext not in LLM_ELIGIBLE_EXTENSIONS or not file.content.strip():
        return []

    result = client.analyze_json(
        CLASSIFY_SYSTEM_PROMPT,
        f"File: {file.rel_path}\n\n{file.content}",
    )
    if not result or not isinstance(result, dict):
        return []

    findings = []
    for item in result.get("findings", []):
        evidence = str(item.get("evidence", "")).strip()
        confidence = "inferred" if verify_evidence(file.content, evidence) else "inferred-unverified"
        findings.append(
            RiskSurface(
                path=file.path,
                rel_path=file.rel_path,
                entry_point=_normalize_entry_point(str(item.get("entry_point", "unknown"))),
                rationale=str(item.get("rationale", "")),
                line=_line_number_from_snippet(file.content, evidence) if confidence == "inferred" else None,
                confidence=confidence,
            )
        )
    return findings


def classify_risk_surface(state: GraphState) -> GraphState:
    surfaces: list[RiskSurface] = []
    client = GroqClient()

    for file in state.files:
        filename = file.rel_path.rsplit("/", 1)[-1]
        scan_content = mask_python_docstrings(file.content) if filename.endswith(".py") else file.content
        for entry_point, pattern in ENTRY_POINT_PATTERNS:
            for match in pattern.finditer(scan_content):
                surfaces.append(
                    RiskSurface(
                        path=file.path,
                        rel_path=file.rel_path,
                        entry_point=entry_point,
                        rationale=f"Matched pattern for {entry_point.lower()}.",
                        line=_line_number_from_pos(file.content, match.start()),
                        confidence="confirmed",
                    )
                )

        if client.enabled:
            surfaces.extend(_llm_findings(file, client))

    state.risk_surfaces = surfaces

    confirmed = sum(1 for s in surfaces if s.confidence == "confirmed")
    inferred = sum(1 for s in surfaces if s.confidence == "inferred")
    unverified = sum(1 for s in surfaces if s.confidence == "inferred-unverified")

    if client.enabled:
        state.findings.append(
            f"Identified {len(surfaces)} risk surfaces "
            f"({confirmed} confirmed, {inferred} inferred, {unverified} inferred-unverified)"
        )
    else:
        state.findings.append(f"Identified {len(surfaces)} risk surfaces (static rules only, no LLM call made)")

    return state
