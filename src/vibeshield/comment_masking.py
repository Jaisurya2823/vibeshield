from __future__ import annotations

import re

_PY_TRIPLE_QUOTED = re.compile(r'("""|\'\'\')(.*?)\1', re.DOTALL)


def mask_python_docstrings(content: str) -> str:
    def _mask(match: re.Match) -> str:
        return "".join(ch if ch == "\n" else " " for ch in match.group(0))

    return _PY_TRIPLE_QUOTED.sub(_mask, content)
