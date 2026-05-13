"""Detect hidden / obfuscated content in SKILL.md, MCP descriptions,
and bundled markdown files.

Coverage targets the well-known skill-poisoning techniques:

  - Zero-width characters (U+200B..U+200D, U+FEFF)
  - Unicode tag characters (U+E0000..U+E007F) — invisible payloads
  - Right-to-left override (U+202E) and other Bidi controls
  - HTML comments hiding instructions
  - Long base64 blobs in description (>120 chars contiguous base64)
"""

from __future__ import annotations

import re
from pathlib import Path

from skillscan.models import Artifact, ArtifactKind, Finding


_ZERO_WIDTH = re.compile(r"[​-‍﻿]")
_UNICODE_TAGS = re.compile(r"[\U000E0000-\U000E007F]")
_BIDI_CONTROL = re.compile(r"[‪-‮⁦-⁩]")
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_LONG_BASE64 = re.compile(r"(?:[A-Za-z0-9+/=]{120,})")


def _files_to_inspect(artifact: Artifact) -> list[Path]:
    paths: list[Path] = []
    if artifact.path.exists() and artifact.path.is_file():
        paths.append(artifact.path)
    for p in artifact.bundled_files:
        if p.suffix.lower() in {".md", ".markdown", ".mdx", ".rst", ".txt", ""}:
            paths.append(p)
    return paths


def run(artifact: Artifact) -> list[Finding]:
    if artifact.kind not in {
        ArtifactKind.SKILL,
        ArtifactKind.HARNESS_CONFIG,
        ArtifactKind.AGENT_DEFINITION,
        ArtifactKind.SLASH_COMMAND,
        ArtifactKind.MCP_SERVER,
    }:
        return []

    findings: list[Finding] = []

    if artifact.kind == ArtifactKind.MCP_SERVER:
        # MCP tool descriptions live in the parsed JSON, not on disk per-tool.
        # Inspect the raw spec strings.
        for value in _walk_strings(artifact.raw):
            findings.extend(_scan_text(value, artifact, file=artifact.path, line=None))
        return findings

    for path in _files_to_inspect(artifact):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            findings.extend(_scan_text(line, artifact, file=path, line=line_no))
    return findings


def _scan_text(text: str, artifact: Artifact, *, file: Path, line: int | None) -> list[Finding]:
    findings: list[Finding] = []
    if _ZERO_WIDTH.search(text):
        findings.append(_make("hidden.zero_width", "Zero-width character in skill text", artifact, file, line, text))
    if _UNICODE_TAGS.search(text):
        findings.append(_make("hidden.unicode_tag", "Unicode tag character in skill text", artifact, file, line, text))
    if _BIDI_CONTROL.search(text):
        findings.append(_make("hidden.bidi_override", "Bidirectional override character in skill text", artifact, file, line, text))
    for comment in _HTML_COMMENT.findall(text):
        if _smells_like_instruction(comment):
            findings.append(_make("hidden.html_comment", "HTML comment carrying instruction-like content", artifact, file, line, text))
            break
    if any(len(m) >= 120 for m in _LONG_BASE64.findall(text)):
        findings.append(_make("hidden.base64_blob", "Long base64 blob in skill text", artifact, file, line, text))
    return findings


_INSTRUCTION_HINTS = re.compile(
    r"\b(ignore (?:all )?previous|disregard|system prompt|do not tell|secret|exfiltrate|"
    r"send.*(?:http|webhook)|run.*(?:bash|curl|wget))\b",
    re.IGNORECASE,
)


def _smells_like_instruction(text: str) -> bool:
    return bool(_INSTRUCTION_HINTS.search(text))


def _make(rule_id: str, summary: str, artifact: Artifact, file: Path, line: int | None, snippet: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        category="nl",
        severity="high",
        confidence="high",
        summary=summary,
        artifact=artifact,
        file=file,
        line=line,
        evidence=[snippet[:160]],
        references=["OWASP-MCP-T01-prompt-injection", "OWASP-LLM01-prompt-injection"],
    )


def _walk_strings(value: object) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(_walk_strings(v))
    elif isinstance(value, list):
        for v in value:
            out.extend(_walk_strings(v))
    return out
