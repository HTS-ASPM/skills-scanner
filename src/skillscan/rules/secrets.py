"""Secret scan across ALL bundled files in a skill — including
test fixtures, examples, and any sibling files.

This deliberately covers files that competing scanners (Snyk Agent Scan,
Cisco AI Skill Scanner, VirusTotal Code Insight) skip — bundled
test/fixture directories are an execution surface from the developer's
side and a known smuggling channel (VentureBeat, Feb 2026).
"""

from __future__ import annotations

import re
from pathlib import Path

from skillscan.models import Artifact, ArtifactKind, Finding


# Conservative high-precision patterns. We trade recall for precision so
# the noise floor stays low; broader heuristics live in a future S2 layer.
_SECRET_RULES: list[tuple[str, re.Pattern[str], str]] = [
    ("secret.openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "OpenAI API key"),
    ("secret.anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "Anthropic API key"),
    ("secret.huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"), "Hugging Face token"),
    ("secret.github_pat", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "GitHub personal access token"),
    ("secret.github_app", re.compile(r"\bghs_[A-Za-z0-9]{20,}\b"), "GitHub app token"),
    ("secret.aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key ID"),
    ("secret.gcp_service_account", re.compile(r'"type"\s*:\s*"service_account"'), "GCP service-account JSON"),
    ("secret.private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Private key"),
    ("secret.slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    ("secret.generic_bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-.=]{20,}\b"), "Bearer token literal"),
]


_SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".tar", ".gz", ".whl"}
_MAX_FILE_BYTES = 1_000_000


def _candidate_files(artifact: Artifact) -> list[Path]:
    files: list[Path] = []
    if artifact.path.exists() and artifact.path.is_file():
        files.append(artifact.path)
    for p in artifact.bundled_files:
        if p.suffix.lower() in _SKIP_SUFFIXES:
            continue
        if not p.is_file():
            continue
        try:
            if p.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        files.append(p)
    return files


def run(artifact: Artifact) -> list[Finding]:
    if artifact.kind in {ArtifactKind.MCP_SERVER}:
        # MCP servers don't bundle a directory; secret check is handled in mcp.run.
        return []
    findings: list[Finding] = []
    for path in _candidate_files(artifact):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for rule_id, pattern, label in _SECRET_RULES:
            for match in pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        category="secret",
                        severity="critical" if "private_key" in rule_id else "high",
                        confidence="high",
                        summary=f"{label} found in {_describe_path(path, artifact)}",
                        artifact=artifact,
                        file=path,
                        line=line_no,
                        evidence=[_redact(match.group(0))],
                        references=["OWASP-MCP-T05-credential-exfil"],
                        metadata={"in_bundled_test": _looks_like_test(path)},
                    )
                )
    return findings


def _describe_path(path: Path, artifact: Artifact) -> str:
    rel = ""
    if artifact.kind == ArtifactKind.SKILL:
        rel = str(path.relative_to(artifact.path.parent)) if artifact.path.parent in path.parents else path.name
    else:
        rel = path.name
    if _looks_like_test(path):
        return f"bundled test/fixture file `{rel}` (execution surface)"
    return f"bundled file `{rel}`"


def _looks_like_test(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    return any(p in parts for p in ("tests", "test", "fixtures", "examples", "example"))


def _redact(secret: str) -> str:
    if len(secret) <= 8:
        return "****"
    return f"{secret[:4]}…{secret[-2:]}"
