"""MCP-server specific rules.

Two surfaces:

  1. The server entry in mcp.json / claude_desktop_config.json — auth
     posture, command/url, env handling.
  2. The tool descriptions (string fields anywhere inside the spec) —
     prompt-injection / tool-poisoning patterns.

Tool description scanning is intentionally conservative; the heavier NL
judge layer arrives in S2.
"""

from __future__ import annotations

import re
from typing import Any

from skillscan.models import Artifact, ArtifactKind, Finding
from skillscan.rules.hidden import _walk_strings  # type: ignore


_INSTRUCTION_INJECTION = re.compile(
    r"(?i)\b(ignore (?:the )?(?:previous|above) instructions|"
    r"do not (?:tell|reveal|mention)|exfiltrate|"
    r"send (?:this|the user'?s) (?:input|prompt|context) to|"
    r"forget (?:everything|all prior)|"
    r"system\s*[:=]\s*you are |"
    r"new instructions for the assistant|"
    r"jailbreak|"
    r"reveal (?:your )?system prompt)\b"
)

_SUSPICIOUS_TOOL_NAMES = {"shell", "sudo", "rm", "exec", "eval", "delete_all"}


def run(artifact: Artifact) -> list[Finding]:
    if artifact.kind != ArtifactKind.MCP_SERVER:
        return []
    findings: list[Finding] = []
    spec = artifact.raw or {}

    findings.extend(_check_auth_posture(artifact, spec))
    findings.extend(_check_command_safety(artifact, spec))
    findings.extend(_check_tool_descriptions(artifact, spec))
    findings.extend(_check_tool_names(artifact, spec))
    return findings


def _check_auth_posture(artifact: Artifact, spec: dict[str, Any]) -> list[Finding]:
    transport = artifact.metadata.get("transport")
    if transport == "http" and not _has_any_auth(spec):
        return [
            Finding(
                rule_id="mcp.auth.http_unauthenticated",
                category="capability",
                severity="critical",
                confidence="high",
                summary=f"MCP server `{artifact.name}` exposes HTTP transport with no auth headers/env",
                artifact=artifact,
                file=artifact.path,
                line=None,
                evidence=[str(spec.get("url", ""))[:160]],
                references=["OWASP-MCP-T02-broken-auth"],
            )
        ]
    return []


def _has_any_auth(spec: dict[str, Any]) -> bool:
    if isinstance(spec.get("headers"), dict) and any(
        k.lower() in {"authorization", "x-api-key"} for k in spec["headers"].keys()
    ):
        return True
    env = spec.get("env") or {}
    if isinstance(env, dict) and any(
        any(token in k.upper() for token in ("TOKEN", "KEY", "SECRET", "PAT"))
        for k in env.keys()
    ):
        return True
    return False


def _check_command_safety(artifact: Artifact, spec: dict[str, Any]) -> list[Finding]:
    args = spec.get("args") or []
    findings: list[Finding] = []
    for arg in args if isinstance(args, list) else []:
        if not isinstance(arg, str):
            continue
        if arg.startswith("http://") or arg.startswith("https://"):
            findings.append(
                Finding(
                    rule_id="mcp.command.url_arg",
                    category="capability",
                    severity="medium",
                    confidence="high",
                    summary=f"MCP server `{artifact.name}` invokes a URL as an argument — pinning recommended",
                    artifact=artifact,
                    file=artifact.path,
                    line=None,
                    evidence=[arg[:160]],
                    references=["OWASP-MCP-T03-supply-chain"],
                )
            )
        if "curl" in arg.lower() and "|" in arg and ("bash" in arg or "sh" in arg):
            findings.append(
                Finding(
                    rule_id="mcp.command.curl_pipe_sh",
                    category="capability",
                    severity="critical",
                    confidence="high",
                    summary=f"MCP server `{artifact.name}` arg pipes curl into a shell",
                    artifact=artifact,
                    file=artifact.path,
                    line=None,
                    evidence=[arg[:160]],
                    references=["OWASP-MCP-T03-supply-chain"],
                )
            )
    return findings


def _check_tool_descriptions(artifact: Artifact, spec: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for value in _walk_strings(spec):
        if _INSTRUCTION_INJECTION.search(value):
            findings.append(
                Finding(
                    rule_id="mcp.description.prompt_injection",
                    category="nl",
                    severity="critical",
                    confidence="medium",
                    summary=f"MCP server `{artifact.name}` description contains instruction-injection language",
                    artifact=artifact,
                    file=artifact.path,
                    line=None,
                    evidence=[value[:200]],
                    references=["OWASP-MCP-T01-tool-poisoning", "OWASP-LLM01-prompt-injection"],
                )
            )
    return findings


def _check_tool_names(artifact: Artifact, spec: dict[str, Any]) -> list[Finding]:
    """Suspicious-name heuristic on the server name itself + any explicit `tools` block."""
    findings: list[Finding] = []
    if artifact.name.lower() in _SUSPICIOUS_TOOL_NAMES:
        findings.append(
            Finding(
                rule_id="mcp.name.suspicious",
                category="capability",
                severity="medium",
                confidence="medium",
                summary=f"MCP server has a suspicious name `{artifact.name}`",
                artifact=artifact,
                file=artifact.path,
                line=None,
                evidence=[artifact.name],
                references=[],
            )
        )
    tools = spec.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if isinstance(tool, dict):
                tname = (tool.get("name") or "").lower()
                if tname in _SUSPICIOUS_TOOL_NAMES:
                    findings.append(
                        Finding(
                            rule_id="mcp.tool.suspicious_name",
                            category="capability",
                            severity="medium",
                            confidence="medium",
                            summary=f"MCP server `{artifact.name}` exposes suspicious tool `{tname}`",
                            artifact=artifact,
                            file=artifact.path,
                            line=None,
                            evidence=[tname],
                            references=[],
                        )
                    )
    return findings
