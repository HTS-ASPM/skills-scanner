"""Core data model for skills-scanner.

Designed to feed CycloneDX 1.6 ML-BOM/SaaSBOM components downstream
(via the shared aibom CDX model). Skills become `service` or
`machine-learning-model` sub-components, MCP servers become `service`
components with their tools as nested capabilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class ArtifactKind(str, Enum):
    SKILL = "skill"                 # Anthropic-style SKILL.md package
    MCP_SERVER = "mcp_server"       # entry in mcp.json / claude_desktop_config.json / etc.
    HARNESS_CONFIG = "harness"      # CLAUDE.md, settings.json, hooks, agents, commands, .cursorrules, ...
    SLASH_COMMAND = "command"
    AGENT_DEFINITION = "agent"
    HOOK = "hook"


class Host(str, Enum):
    CLAUDE_CODE = "claude-code"
    CLAUDE_DESKTOP = "claude-desktop"
    CURSOR = "cursor"
    WINDSURF = "windsurf"
    CODEX_CLI = "codex-cli"
    GEMINI_CLI = "gemini-cli"
    CLINE = "cline"
    AIDER = "aider"
    UNKNOWN = "unknown"


@dataclass
class Artifact:
    """A discovered skill / MCP server / harness config — pre-analysis."""

    kind: ArtifactKind
    host: Host
    name: str
    path: Path
    bundled_files: list[Path] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "host": self.host.value,
            "name": self.name,
            "path": str(self.path),
            "bundled_files": [str(p) for p in self.bundled_files],
            "metadata": self.metadata,
        }


@dataclass
class Finding:
    """A single rule hit on an artifact."""

    rule_id: str
    category: str            # static | nl | capability | provenance | secret
    severity: str            # critical | high | medium | low | info
    confidence: str          # high | medium | low
    summary: str
    artifact: Artifact
    file: Path | None = None
    line: int | None = None
    evidence: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)   # OWASP MCP/LLM Top-10, MITRE ATLAS IDs
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "summary": self.summary,
            "artifact": self.artifact.to_dict(),
            "file": str(self.file) if self.file else None,
            "line": self.line,
            "evidence": self.evidence,
            "references": self.references,
            "metadata": self.metadata,
        }


@dataclass
class ScanResult:
    artifacts: list[Artifact] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifacts": [a.to_dict() for a in self.artifacts],
            "findings": [f.to_dict() for f in self.findings],
            "skipped": self.skipped,
            "summary": {
                "artifacts": len(self.artifacts),
                "findings": len(self.findings),
                "by_kind": _count_by(self.artifacts, lambda a: a.kind.value),
                "by_host": _count_by(self.artifacts, lambda a: a.host.value),
                "by_severity": _count_by(self.findings, lambda f: f.severity),
            },
        }


def _count_by(items, key) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in items:
        k = key(item)
        out[k] = out.get(k, 0) + 1
    return out
