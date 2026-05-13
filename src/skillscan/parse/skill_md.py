"""Minimal SKILL.md parser.

Anthropic skill format:
    ---
    name: my-skill
    description: ...
    allowed-tools: ["Read", "Bash"]
    disable-model-invocation: false
    ---
    <markdown body>

We deliberately avoid a YAML dependency at this stage — the frontmatter
field set is small and well-known. We support quoted/unquoted scalars,
inline JSON arrays, and inline JSON objects. Full YAML can be swapped in
later behind this same function signature.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_FRONTMATTER_RE = re.compile(
    r"\A---\s*\n(?P<front>.*?)\n---\s*\n(?P<body>.*)\Z",
    re.DOTALL,
)


def parse_skill_md(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return {"body": text}
    front = _parse_frontmatter(match.group("front"))
    front["body"] = match.group("body")
    return front


def _parse_frontmatter(block: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for raw_line in block.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        result[key] = _coerce(value)
    return result


def _coerce(value: str) -> Any:
    if not value:
        return None
    if value[0] in "[{":
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.lower() in {"null", "~"}:
        return None
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    return value
