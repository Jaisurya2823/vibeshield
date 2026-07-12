from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class FileRecord:
    path: str
    rel_path: str
    content: str = ""
    truncated: bool = False


@dataclass
class RiskSurface:
    path: str
    rel_path: str
    entry_point: str
    rationale: str
    line: int | None = None
    confidence: str = "confirmed"


@dataclass
class Vulnerability:
    path: str
    rel_path: str
    category: str
    severity: str
    summary: str
    evidence: str
    remediation: str = ""
    line: int | None = None
    confidence: str = "confirmed"


@dataclass
class GraphState:
    target_path: str
    files: List[FileRecord] = field(default_factory=list)
    risk_surfaces: List[RiskSurface] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    unreadable_files: List[str] = field(default_factory=list)
    llm_error: str | None = None
