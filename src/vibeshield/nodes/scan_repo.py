from __future__ import annotations

from pathlib import Path

from ..file_reader import read_file
from ..state import FileRecord, GraphState


def scan_repository(state: GraphState) -> GraphState:
    target = Path(state.target_path).resolve()
    files: list[FileRecord] = []
    unreadable: list[str] = []
    excluded_dirs = {
        ".git", "__pycache__", ".venv", "venv", "node_modules",
        "vendor", "dist", "build", ".next", "coverage",
    }
    for path in sorted(target.rglob("*")):
        if any(part in excluded_dirs for part in path.parts):
            continue
        try:
            if path.is_dir():
                continue
        except OSError:
            pass
        if path.name == ".vibeshield-baseline.json":
            continue
        if path.suffix.lower() in {
            ".pyc", ".pyo", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".bz2",
            ".pdf", ".exe", ".dll", ".so", ".dylib", ".woff", ".woff2",
            ".ttf", ".eot", ".mp3", ".mp4", ".wav", ".avi", ".mov",
        }:
            continue
        if path.name.endswith(".min.js") or path.name.endswith(".min.css"):
            continue

        rel = str(path.relative_to(target)) if target in path.parents else str(path)
        try:
            record = read_file(path, root=target)
        except IsADirectoryError:
            continue
        except (OSError, PermissionError, UnicodeError):
            unreadable.append(rel)
            continue
        files.append(record)

    state.files = files
    state.unreadable_files = unreadable
    state.findings.append(f"Scanned {len(files)} files")
    return state
