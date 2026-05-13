"""Cross-skill collusion graph.

Three signals across the full set of discovered artifacts:

  1. exfil_chain_candidates
     A pair of skills where one reads sensitive data (declares Read /
     reads `~/.aws/credentials` / `~/.ssh/`) and the other has outbound
     network capability (WebFetch declared, or static.shell.exfil_egress
     fired). Together they form an exfil pipeline — even if neither
     alone trips a rule.

  2. shared_mcp_blast_radius
     Multiple skills granting access to the same high-priv MCP server.
     Any of them being compromised hands attackers shared infrastructure.

  3. tool_consolidation
     Skills whose union of allowed-tools exceeds a configurable
     threshold (default 5). A user enabling many small skills can
     accidentally re-create wildcard agency.

These signals are *cross-artifact* — they live outside the per-artifact
rule loop and are wired in cli.py after run_rules completes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations
from pathlib import Path

from skillscan.models import Artifact, ArtifactKind, Finding, Host


_SENSITIVE_READ_HINTS = (
    "~/.aws/", "~/.ssh/", ".git-credentials", "credentials", "id_rsa",
)


@dataclass
class _ArtifactView:
    artifact: Artifact
    declared_tools: set[str] = field(default_factory=set)
    reads_sensitive: bool = False
    has_egress: bool = False
    mcp_servers: set[str] = field(default_factory=set)


def analyze(artifacts: list[Artifact], findings: list[Finding], *, tool_union_threshold: int = 5) -> list[Finding]:
    views = _build_views(artifacts, findings)
    out: list[Finding] = []
    out.extend(_exfil_chain(views))
    out.extend(_shared_mcp(views))
    out.extend(_tool_consolidation(views, threshold=tool_union_threshold))
    return out


# --------------------------------------------------------------------------- #

def _build_views(artifacts: list[Artifact], findings: list[Finding]) -> list[_ArtifactView]:
    views: dict[str, _ArtifactView] = {}
    for artifact in artifacts:
        key = f"{artifact.host.value}:{artifact.kind.value}:{artifact.name}"
        view = views.setdefault(key, _ArtifactView(artifact=artifact))
        if artifact.kind == ArtifactKind.SKILL:
            view.declared_tools.update(_normalize_tools(artifact.metadata.get("allowed_tools")))
        if artifact.kind == ArtifactKind.MCP_SERVER:
            view.mcp_servers.add(artifact.name)

    # Cross-reference findings to set behavioral flags per artifact.
    keys_by_artifact: dict[id, str] = {id(v.artifact): k for k, v in views.items()}
    for finding in findings:
        key = keys_by_artifact.get(id(finding.artifact))
        if key is None:
            continue
        view = views[key]
        if finding.rule_id == "static.shell.exfil_egress":
            view.has_egress = True
        if finding.rule_id in {"static.shell.ssh_key_read", "static.shell.aws_creds_read", "static.shell.git_credential_read"}:
            view.reads_sensitive = True

    # Boost: declared WebFetch counts as egress capability.
    for view in views.values():
        if "WebFetch" in view.declared_tools:
            view.has_egress = True
        if "Read" in view.declared_tools and any(_artifact_text_hints(view.artifact, _SENSITIVE_READ_HINTS)):
            view.reads_sensitive = True

    return list(views.values())


def _exfil_chain(views: list[_ArtifactView]) -> list[Finding]:
    findings: list[Finding] = []
    skills = [v for v in views if v.artifact.kind == ArtifactKind.SKILL]
    for a, b in combinations(skills, 2):
        if (a.reads_sensitive and b.has_egress) or (b.reads_sensitive and a.has_egress):
            reader = a if a.reads_sensitive else b
            sender = b if reader is a else a
            findings.append(
                Finding(
                    rule_id="collusion.exfil_chain",
                    category="collusion",
                    severity="high",
                    confidence="medium",
                    summary=(
                        f"Exfil-chain candidate: skill `{reader.artifact.name}` reads sensitive data "
                        f"and skill `{sender.artifact.name}` can reach external endpoints"
                    ),
                    artifact=reader.artifact,
                    file=reader.artifact.path,
                    line=None,
                    evidence=[reader.artifact.name, sender.artifact.name],
                    references=["OWASP-LLM06-sensitive-info-disclosure", "OWASP-MCP-T07-data-exfil"],
                    metadata={"reader": reader.artifact.name, "sender": sender.artifact.name},
                )
            )
    return findings


def _shared_mcp(views: list[_ArtifactView]) -> list[Finding]:
    findings: list[Finding] = []
    skills = [v for v in views if v.artifact.kind == ArtifactKind.SKILL]
    mcps = [v for v in views if v.artifact.kind == ArtifactKind.MCP_SERVER]
    if not mcps or len(skills) < 2:
        return findings
    # If 3+ skills exist alongside any single MCP server, surface a shared-blast-radius signal.
    for mcp in mcps:
        if len(skills) >= 3:
            findings.append(
                Finding(
                    rule_id="collusion.shared_mcp_blast_radius",
                    category="collusion",
                    severity="medium",
                    confidence="medium",
                    summary=(
                        f"{len(skills)} skills share the same agent host that exposes MCP server "
                        f"`{mcp.artifact.name}` — a single skill compromise reaches the whole MCP surface"
                    ),
                    artifact=mcp.artifact,
                    file=mcp.artifact.path,
                    line=None,
                    evidence=[mcp.artifact.name] + [s.artifact.name for s in skills[:5]],
                    references=["OWASP-MCP-T03-supply-chain", "OWASP-LLM08-excessive-agency"],
                    metadata={"mcp_server": mcp.artifact.name, "skill_count": len(skills)},
                )
            )
    return findings


def _tool_consolidation(views: list[_ArtifactView], *, threshold: int) -> list[Finding]:
    skills = [v for v in views if v.artifact.kind == ArtifactKind.SKILL]
    if not skills:
        return []
    union: set[str] = set()
    for v in skills:
        union.update(v.declared_tools)
    union.discard("*")
    if len(union) < threshold:
        return []
    representative = skills[0].artifact
    return [
        Finding(
            rule_id="collusion.tool_consolidation",
            category="collusion",
            severity="medium",
            confidence="medium",
            summary=(
                f"Combined skill set declares {len(union)} distinct tools — recreates wildcard agency in aggregate"
            ),
            artifact=representative,
            file=representative.path,
            line=None,
            evidence=sorted(union)[:10],
            references=["OWASP-LLM08-excessive-agency"],
            metadata={"distinct_tools": sorted(union), "skill_count": len(skills), "threshold": threshold},
        )
    ]


# --------------------------------------------------------------------------- #

def _normalize_tools(value) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return []


def _artifact_text_hints(artifact: Artifact, hints: tuple[str, ...]) -> list[bool]:
    out: list[bool] = []
    for path in artifact.bundled_files:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for hint in hints:
            if hint in text:
                out.append(True)
                return out
    return out
