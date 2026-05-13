"""Capability-graph rule: compare a skill's declared `allowed-tools`
against tool-usage signals in the bundled code.

Two findings emitted:

  capability.overscoped_unused   declared tool never appears in bundle
                                 (skill asks for more than it uses)
  capability.bypass_attempt      bundle uses a capability that is NOT in
                                 the declared tool allowlist (skill needs
                                 more than it asked for — possible bypass
                                 or accidental scope leak)

Tool-usage detection is heuristic and intentionally conservative — any
truly suspicious pattern is also picked up by rules.static.
"""

from __future__ import annotations

import re
from pathlib import Path

from skillscan.models import Artifact, ArtifactKind, Finding


# Tool name -> regex hints we look for in bundled .py / .sh / .js / .ts code.
_TOOL_USAGE_HINTS: dict[str, list[re.Pattern[str]]] = {
    "Bash": [
        re.compile(r"\b(subprocess\.(?:run|Popen|call|check_output)|os\.system|os\.popen)\s*\("),
        re.compile(r"^\s*#!\s*/.*(bash|sh|zsh)\b", re.MULTILINE),
        re.compile(r"`[^`]+`"),
        re.compile(r"\b(execvp|spawnvp)\s*\("),
    ],
    "Edit": [re.compile(r"\.write_text\(|\.write\(|open\(\s*['\"][^'\"]+['\"]\s*,\s*['\"][wax]")],
    "Write": [re.compile(r"\.write_text\(|\.write\(|open\(\s*['\"][^'\"]+['\"]\s*,\s*['\"][wax]")],
    "Read": [re.compile(r"\.read_text\(|\.read\(\)|open\(\s*['\"][^'\"]+['\"]\s*,\s*['\"]r")],
    "WebFetch": [
        re.compile(r"\b(requests\.(?:get|post)|urllib\.request|httpx\.|aiohttp\.|curl\b|wget\b)"),
    ],
    "WebSearch": [
        re.compile(r"google\.|duckduckgo|serper\.|tavily|bing\.search"),
    ],
}


_SCAN_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".sh", ".bash"}


def run(artifact: Artifact) -> list[Finding]:
    if artifact.kind != ArtifactKind.SKILL:
        return []
    declared_raw = (artifact.metadata or {}).get("allowed_tools")
    declared = _normalize(declared_raw)
    if declared is None:
        return []  # frontmatter rule handles missing allowed-tools

    used = _detect_used_tools(artifact)

    findings: list[Finding] = []
    declared_set = set(declared)
    used_set = set(used)

    # OVERSCOPED: declared but never used
    if declared_set != {"*"}:
        for tool in sorted(declared_set - used_set):
            if tool in _TOOL_USAGE_HINTS:
                findings.append(_make(
                    "capability.overscoped_unused",
                    f"`allowed-tools` declares `{tool}` but it is never used in the skill bundle",
                    artifact,
                    severity="medium",
                    metadata={"tool": tool, "declared": sorted(declared_set), "used": sorted(used_set)},
                ))

    # BYPASS: used but not declared (skip when wildcard is granted)
    if declared_set != {"*"}:
        for tool in sorted(used_set - declared_set):
            findings.append(_make(
                "capability.bypass_attempt",
                f"Skill uses `{tool}` capability but does not declare it in `allowed-tools`",
                artifact,
                severity="high",
                metadata={"tool": tool, "declared": sorted(declared_set), "used": sorted(used_set)},
            ))

    return findings


def _detect_used_tools(artifact: Artifact) -> list[str]:
    """Return the set of tool names whose hint regexes match anywhere in the
    skill's bundled code files."""
    used: set[str] = set()
    files = [p for p in artifact.bundled_files if p.suffix.lower() in _SCAN_SUFFIXES and p.is_file()]
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for tool, patterns in _TOOL_USAGE_HINTS.items():
            if any(p.search(text) for p in patterns):
                used.add(tool)
    return sorted(used)


def _normalize(value: object) -> list[str] | None:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        if value.strip() in {"*", "all"}:
            return ["*"]
        return [value]
    return None


def _make(rule_id: str, summary: str, artifact: Artifact, *, severity: str, metadata: dict) -> Finding:
    return Finding(
        rule_id=rule_id,
        category="capability",
        severity=severity,
        confidence="medium",
        summary=summary,
        artifact=artifact,
        file=artifact.path,
        line=None,
        evidence=[],
        references=["OWASP-LLM08-excessive-agency", "NIST-AI-RMF-GV-3.2"],
        metadata=metadata,
    )
