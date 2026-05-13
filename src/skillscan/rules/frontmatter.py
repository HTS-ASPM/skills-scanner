"""SKILL.md frontmatter validation + capability sanity checks."""

from __future__ import annotations

from skillscan.models import Artifact, ArtifactKind, Finding


_REQUIRED_FIELDS = ("name", "description")
_OVERSCOPED_TOOL_TOKENS = {"*", "all", "Bash", "Edit", "Write", "WebFetch", "WebSearch"}


def run(artifact: Artifact) -> list[Finding]:
    if artifact.kind != ArtifactKind.SKILL:
        return []
    findings: list[Finding] = []
    raw = artifact.raw or {}
    for field in _REQUIRED_FIELDS:
        if not raw.get(field):
            findings.append(_make(
                "frontmatter.missing_required",
                f"SKILL.md missing required `{field}` frontmatter field",
                artifact,
                severity="high",
            ))

    description = raw.get("description") or ""
    if isinstance(description, str) and len(description) > 1024:
        findings.append(_make(
            "frontmatter.long_description",
            "SKILL.md description is unusually long — possible payload-in-description",
            artifact,
            severity="medium",
        ))

    allowed_tools = raw.get("allowed-tools")
    if allowed_tools is None:
        findings.append(_make(
            "frontmatter.missing_allowed_tools",
            "SKILL.md does not declare `allowed-tools` — defaults to model's full toolset",
            artifact,
            severity="medium",
        ))
    elif isinstance(allowed_tools, list):
        risky = sorted({t for t in allowed_tools if t in _OVERSCOPED_TOOL_TOKENS})
        if risky:
            findings.append(_make(
                "frontmatter.overscoped_tools",
                f"SKILL.md grants high-blast-radius tool(s): {', '.join(risky)}",
                artifact,
                severity="high",
                metadata={"tools": risky},
            ))
    elif isinstance(allowed_tools, str) and allowed_tools.strip() in {"*", "all"}:
        findings.append(_make(
            "frontmatter.allowed_tools_wildcard",
            "SKILL.md allowed-tools is wildcard — every tool granted",
            artifact,
            severity="critical",
        ))

    if raw.get("disable-model-invocation") is False or raw.get("disable-model-invocation") is None:
        # auto-invocation isn't intrinsically bad, but combined with overscoped
        # tools it's how guidance-injection attacks land. Flag at low severity.
        findings.append(_make(
            "frontmatter.auto_invocation",
            "SKILL.md does not set `disable-model-invocation: true` — model auto-invokes when matched",
            artifact,
            severity="low",
            confidence="medium",
        ))

    return findings


def _make(
    rule_id: str,
    summary: str,
    artifact: Artifact,
    *,
    severity: str = "medium",
    confidence: str = "high",
    metadata: dict | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category="capability",
        severity=severity,
        confidence=confidence,
        summary=summary,
        artifact=artifact,
        file=artifact.path,
        line=None,
        evidence=[],
        references=["OWASP-LLM08-excessive-agency"],
        metadata=metadata or {},
    )
