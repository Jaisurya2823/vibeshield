from __future__ import annotations

from pathlib import Path

from .state import FileRecord

MAX_READ_CHARS = 200_000

_BOM_ENCODINGS: list[tuple[bytes, str]] = [
    (b"\xff\xfe\x00\x00", "utf-32"),
    (b"\x00\x00\xfe\xff", "utf-32"),
    (b"\xff\xfe", "utf-16"),
    (b"\xfe\xff", "utf-16"),
    (b"\xef\xbb\xbf", "utf-8-sig"),
]


def _decode_bytes(raw: bytes) -> str:
    for bom, encoding in _BOM_ENCODINGS:
        if raw.startswith(bom):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                break
    return raw.decode("utf-8", errors="replace")


def read_file(path: str | Path, *, root: str | Path | None = None, max_chars: int = MAX_READ_CHARS) -> FileRecord:
    file_path = Path(path)
    if root is None:
        root = file_path.parent
    root_path = Path(root).resolve()
    file_path = file_path.resolve()
    try:
        rel_path = file_path.relative_to(root_path).as_posix()
    except ValueError:
        rel_path = file_path.name
    raw_bytes = file_path.read_bytes()
    content = _decode_bytes(raw_bytes)
    truncated = len(content) > max_chars
    if truncated:
        content = content[:max_chars]
    return FileRecord(path=str(file_path), rel_path=rel_path, content=content, truncated=truncated)
