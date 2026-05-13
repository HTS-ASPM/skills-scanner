"""Allowlist policy engine.

Loads a JSON allowlist file describing which skills + MCP servers an
organization permits, and emits findings for anything not allowlisted.

Allowlist file shape:

  {
    "skills": [
      {"name": "review", "host": "claude-code", "tools": ["Read", "Bash"]},
      {"name": "loop", "host": "claude-code"}
    ],
    "mcp_servers": [
      {"name": "filesystem", "host": "claude-code"},
      {"name": "github"}
    ],
    "deny_tools": ["WebFetch", "WebSearch"]
  }

Rules emitted:
  policy.allowlist.skill_not_listed         (high)
  policy.allowlist.mcp_not_listed           (high)
  policy.allowlist.tool_not_in_skill_grant  (medium)
  policy.allowlist.deny_tool_used           (critical)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skillscan.models import Artifact, ArtifactKind, Finding


@dataclass
class Allowlist:
    skills: list[dict[str, Any]]
    mcp_servers: list[dict[str, Any]]
    deny_tools: list[str]

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Allowlist":
        return cls(
            skills=list(payload.get("skills", [])),
            mcp_servers=list(payload.get("mcp_servers", [])),
            deny_tools=list(payload.get("deny_tools", [])),
        )

    @classmethod
    def from_file(cls, path: Path) -> "Allowlist":
        text = path.read_text(encoding="utf-8")
        return cls.from_dict(json.loads(text))


def evaluate(artifacts: list[Artifact], allowlist: Allowlist) -> list[Finding]:
    findings: list[Finding] = []
    for artifact in artifacts:
        if artifact.kind == ArtifactKind.SKILL:
            findings.extend(_evaluate_skill(artifact, allowlist))
        elif artifact.kind == ArtifactKind.MCP_SERVER:
            findings.extend(_evaluate_mcp(artifact, allowlist))
    return findings


def _evaluate_skill(artifact: Artifact, allowlist: Allowlist) -> list[Finding]:
    findings: list[Finding] = []
    entry = _match_entry(artifact, allowlist.skills)
    if entry is None:
        findings.append(_make(
            "policy.allowlist.skill_not_listed",
            f"Skill `{artifact.name}` is not in the org allowlist",
            artifact, severity="high",
        ))
        return findings  # short-circuit further skill rules

    declared = _declared_tools(artifact)
    permitted = set(entry.get("tools") or [])

    # tools used but not in this skill's grant
    if permitted:
        not_granted = sorted(declared - permitted)
        if not_granted:
            findings.append(_make(
                "policy.allowlist.tool_not_in_skill_grant",
                f"Skill `{artifact.name}` declares tools beyond its allowlist grant: "
                + ", ".join(not_granted),
                artifact, severity="medium",
                metadata={"declared": sorted(declared), "permitted": sorted(permitted)},
            ))

    # deny-tools take precedence over the per-skill grant
    deny_violations = sorted(set(allowlist.deny_tools) & declared)
    if deny_violations:
        findings.append(_make(
            "policy.allowlist.deny_tool_used",
            f"Skill `{artifact.name}` declares an org-deny tool: " + ", ".join(deny_violations),
            artifact, severity="critical",
            metadata={"deny_tools": sorted(allowlist.deny_tools)},
        ))

    return findings


def _evaluate_mcp(artifact: Artifact, allowlist: Allowlist) -> list[Finding]:
    if _match_entry(artifact, allowlist.mcp_servers) is not None:
        return []
    return [_make(
        "policy.allowlist.mcp_not_listed",
        f"MCP server `{artifact.name}` is not in the org allowlist",
        artifact, severity="high",
    )]


def _match_entry(artifact: Artifact, entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    for entry in entries:
        if entry.get("name") != artifact.name:
            continue
        host = entry.get("host")
        if host and host != artifact.host.value:
            continue
        return entry
    return None


def _declared_tools(artifact: Artifact) -> set[str]:
    raw = (artifact.metadata or {}).get("allowed_tools")
    if isinstance(raw, list):
        return {str(t) for t in raw}
    if isinstance(raw, str):
        return {raw}
    return set()


def _make(rule_id: str, summary: str, artifact: Artifact, *, severity: str, metadata: dict | None = None) -> Finding:
    return Finding(
        rule_id=rule_id,
        category="policy",
        severity=severity,
        confidence="high",
        summary=summary,
        artifact=artifact,
        file=artifact.path,
        line=None,
        evidence=[],
        references=["OWASP-LLM08-excessive-agency"],
        metadata=metadata or {},
    )
