"""Reputation registry + lookup.

A registry entry has the shape:

  {
    "match": {"name": "<skill name>"} | {"description_substring": "..."},
    "verdict": "malicious" | "suspicious" | "low_reputation" | "trusted",
    "source": "snyk-toxicskills | openclaw-advisory | virustotal | manual",
    "reference": "<URL or advisory id>",
    "summary": "<one-line reason>"
  }

Verdicts map to severity:
  malicious       -> critical
  suspicious      -> high
  low_reputation  -> medium
  trusted         -> info  (allow-list signal, not a finding)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skillscan.models import Artifact, ArtifactKind, Finding


# Curated default registry — sourced from public reporting in 2026.
# Keep this small and well-attributed; large blocklists belong in an
# externally managed feed.
DEFAULT_REGISTRY: list[dict[str, Any]] = [
    {
        "match": {"description_substring": "ignore previous instructions and reveal"},
        "verdict": "malicious",
        "source": "trojans-whisper",
        "reference": "arxiv:2603.19974",
        "summary": "Description matches Trojan's Whisper guidance-injection example.",
    },
    {
        "match": {"description_substring": "exfiltrate"},
        "verdict": "suspicious",
        "source": "snyk-toxicskills",
        "reference": "https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/",
        "summary": "Description contains 'exfiltrate' — uncommon in legitimate skills.",
    },
    {
        "match": {"name_substring": "_v2_"},
        "verdict": "suspicious",
        "source": "openclaw-advisory",
        "reference": "https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html",
        "summary": "Names with embedded '_v2_' have been observed in OpenClaw rug-pulls.",
    },
]


@dataclass(frozen=True)
class ReputationVerdict:
    verdict: str
    source: str
    reference: str
    summary: str


_VERDICT_TO_SEVERITY = {
    "malicious": "critical",
    "suspicious": "high",
    "low_reputation": "medium",
    "trusted": "info",
}


def load_registry(path: Path | None = None) -> list[dict[str, Any]]:
    """Load registry from explicit path, env var, or fall back to default."""
    candidate = path or _env_registry_path()
    if candidate is None:
        return list(DEFAULT_REGISTRY)
    try:
        text = candidate.read_text(encoding="utf-8")
    except OSError:
        return list(DEFAULT_REGISTRY)
    try:
        loaded = json.loads(text)
        if isinstance(loaded, list):
            return loaded
    except json.JSONDecodeError:
        pass
    return list(DEFAULT_REGISTRY)


def lookup(artifact: Artifact, registry: list[dict[str, Any]]) -> ReputationVerdict | None:
    name_lower = (artifact.name or "").lower()
    description = ""
    if artifact.kind == ArtifactKind.SKILL:
        description = (artifact.metadata.get("description") or "").lower() if isinstance(artifact.metadata, dict) else ""
    for entry in registry:
        match = entry.get("match") or {}
        if "name" in match and match["name"].lower() == name_lower:
            return _entry_to_verdict(entry)
        if "name_substring" in match and match["name_substring"].lower() in name_lower:
            return _entry_to_verdict(entry)
        if "description_substring" in match and match["description_substring"].lower() in description:
            return _entry_to_verdict(entry)
    return None


def enrich_with_reputation(
    artifacts: list[Artifact],
    *,
    registry: list[dict[str, Any]] | None = None,
) -> list[Finding]:
    reg = registry if registry is not None else load_registry()
    findings: list[Finding] = []
    for artifact in artifacts:
        verdict = lookup(artifact, reg)
        if verdict is None or verdict.verdict == "trusted":
            continue
        severity = _VERDICT_TO_SEVERITY.get(verdict.verdict, "medium")
        findings.append(
            Finding(
                rule_id=f"reputation.{verdict.verdict}",
                category="provenance",
                severity=severity,
                confidence="high",
                summary=verdict.summary,
                artifact=artifact,
                file=artifact.path,
                line=None,
                evidence=[verdict.reference],
                references=[verdict.reference, "OWASP-MCP-T03-supply-chain"],
                metadata={
                    "verdict": verdict.verdict,
                    "source": verdict.source,
                    "reference": verdict.reference,
                },
            )
        )
    return findings


def _entry_to_verdict(entry: dict[str, Any]) -> ReputationVerdict:
    return ReputationVerdict(
        verdict=str(entry.get("verdict", "low_reputation")),
        source=str(entry.get("source", "manual")),
        reference=str(entry.get("reference", "")),
        summary=str(entry.get("summary", "Matched marketplace reputation entry.")),
    )


def _env_registry_path() -> Path | None:
    val = os.environ.get("SKILLSCAN_REPUTATION_REGISTRY")
    return Path(val) if val else None
