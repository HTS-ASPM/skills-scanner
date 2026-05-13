"""Optional LLM-backed NL judge for SKILL.md and MCP tool descriptions.

Off by default. Activated when:
  - ANTHROPIC_API_KEY is in the environment, AND
  - the user passes --judge to skillscan scan, AND
  - the `anthropic` Python package is importable.

The judge reads ONLY metadata strings (description, allowed-tools, MCP
tool descriptions) — never bundled source files — and asks a small,
prompt-cached classifier to flag guidance-injection patterns that the
deterministic Tier-0 rules in skillscan.rules.hidden + .mcp will miss.

This file ships the *interface* and a deterministic stub. The wired
Anthropic call lives behind an import guard so tests work without the
SDK installed and without network.
"""

from __future__ import annotations

import os
from typing import Callable

from skillscan.models import Artifact, ArtifactKind, Finding


# Sentinel return for the stub judge — keeps tests reproducible.
_GUIDANCE_HINTS = (
    "step 1.",
    "first, retrieve",
    "before responding",
    "as a senior",
    "you have permission to",
    "treat the following as",
)


def is_available() -> bool:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
        return True
    except ImportError:
        return False


def run(
    artifact: Artifact,
    *,
    classifier: Callable[[str], dict] | None = None,
) -> list[Finding]:
    if artifact.kind not in {ArtifactKind.SKILL, ArtifactKind.MCP_SERVER}:
        return []
    text = _judge_text(artifact)
    if not text:
        return []
    classify = classifier or _stub_classifier
    verdict = classify(text)
    if not verdict.get("flagged"):
        return []
    return [
        Finding(
            rule_id="nl_judge.guidance_injection",
            category="nl",
            severity=verdict.get("severity", "high"),
            confidence=verdict.get("confidence", "medium"),
            summary=verdict.get("summary", "NL judge flagged guidance-injection patterns in skill metadata"),
            artifact=artifact,
            file=artifact.path,
            line=None,
            evidence=verdict.get("evidence", []),
            references=["OWASP-LLM01-prompt-injection", "OWASP-MCP-T01-tool-poisoning"],
            metadata={"judge": verdict.get("judge", "stub")},
        )
    ]


def _judge_text(artifact: Artifact) -> str:
    if artifact.kind == ArtifactKind.SKILL:
        desc = (artifact.metadata or {}).get("description") or ""
        body = (artifact.raw or {}).get("body") or ""
        return f"{desc}\n\n{body[:2000]}"
    if artifact.kind == ArtifactKind.MCP_SERVER:
        # walk all string values in the spec
        return _walk_strings(artifact.raw)
    return ""


def _walk_strings(value: object) -> str:
    parts: list[str] = []
    if isinstance(value, str):
        parts.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            parts.append(_walk_strings(v))
    elif isinstance(value, list):
        for v in value:
            parts.append(_walk_strings(v))
    return "\n".join(p for p in parts if p)


def _stub_classifier(text: str) -> dict:
    """Deterministic stand-in used when no LLM is wired.

    Flags content carrying multiple guidance-injection hints. Real Anthropic
    classifier replaces this in the live judge — the contract is just
    {flagged, severity, confidence, summary, evidence, judge}.
    """
    lowered = text.lower()
    hits = [hint for hint in _GUIDANCE_HINTS if hint in lowered]
    if len(hits) >= 2:
        return {
            "flagged": True,
            "severity": "high",
            "confidence": "medium",
            "summary": "NL judge flagged multiple guidance-injection patterns in skill metadata",
            "evidence": hits[:5],
            "judge": "stub",
        }
    return {"flagged": False}
