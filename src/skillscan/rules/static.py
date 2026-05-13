"""Static analysis of bundled files in a skill.

Looks for unsafe code patterns regardless of whether the file is on the
agent execution surface (referenced from SKILL.md) or the developer
execution surface (tests/fixtures/examples) — both have been used in
real-world supply-chain attacks against agent skills.
"""

from __future__ import annotations

import re
from pathlib import Path

from skillscan.models import Artifact, ArtifactKind, Finding


# (rule_id, summary, severity, pattern)
_STATIC_RULES: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("static.shell.curl_pipe_sh", "curl|wget piped to a shell — supply-chain risk", "critical",
     re.compile(r"(curl|wget)\s+[^\n]*\|\s*(bash|sh|zsh)", re.IGNORECASE)),
    ("static.shell.rm_rf_root", "rm -rf operating near filesystem root", "critical",
     re.compile(r"\brm\s+-rf\s+(/|~|\$HOME|\.\.)")),
    ("static.shell.exfil_egress", "Unrestricted network egress in skill code", "high",
     re.compile(r"(curl|wget)\s+[^\n]*https?://[^\s]+", re.IGNORECASE)),
    ("static.python.eval_exec", "Use of eval() / exec() in skill code", "high",
     re.compile(r"(?<![A-Za-z_])(eval|exec)\s*\(")),
    ("static.python.subprocess_shell_true", "subprocess call with shell=True", "high",
     re.compile(r"subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True", re.DOTALL)),
    ("static.python.os_system", "Use of os.system() in skill code", "high",
     re.compile(r"\bos\.system\s*\(")),
    ("static.python.pickle_load", "pickle.load on untrusted data", "high",
     re.compile(r"\bpickle\.(?:load|loads)\s*\(")),
    ("static.python.requests_post_unsafe", "Outbound HTTP POST to non-allowlisted host", "medium",
     re.compile(r"requests\.(?:post|put|patch)\s*\([^)]*https?://", re.DOTALL)),
    ("static.shell.env_dump", "Environment dump (printenv / env)", "medium",
     re.compile(r"\b(printenv|env\s*\|\s*(grep|tee)|cat\s+/proc/self/environ)\b")),
    ("static.shell.ssh_key_read", "Reads SSH private key material", "high",
     re.compile(r"~/\.ssh/id_(rsa|ed25519|ecdsa)|\.ssh/authorized_keys")),
    ("static.shell.aws_creds_read", "Reads AWS credentials file", "high",
     re.compile(r"~/\.aws/credentials|\.aws/config")),
    ("static.shell.git_credential_read", "Reads git credentials", "high",
     re.compile(r"git\s+config\s+--global\s+credential|~/\.git-credentials")),
]


_SCAN_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".sh", ".bash", ".zsh", ".rb",
    ".go", ".rs", ".php", ".pl", ".lua", ".ps1", ".cmd", ".bat",
}


def _candidate_files(artifact: Artifact) -> list[Path]:
    files: list[Path] = []
    if artifact.path.exists() and artifact.path.suffix.lower() in _SCAN_SUFFIXES:
        files.append(artifact.path)
    for p in artifact.bundled_files:
        if p.suffix.lower() in _SCAN_SUFFIXES and p.is_file():
            files.append(p)
    return files


def run(artifact: Artifact) -> list[Finding]:
    if artifact.kind not in {
        ArtifactKind.SKILL,
        ArtifactKind.AGENT_DEFINITION,
        ArtifactKind.SLASH_COMMAND,
        ArtifactKind.HOOK,
    }:
        return []
    findings: list[Finding] = []
    for path in _candidate_files(artifact):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for rule_id, summary, severity, pattern in _STATIC_RULES:
            for match in pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        category="static",
                        severity=severity,
                        confidence="high",
                        summary=summary,
                        artifact=artifact,
                        file=path,
                        line=line_no,
                        evidence=[match.group(0)[:160]],
                        references=_refs_for(rule_id),
                        metadata={"in_bundled_test": _looks_like_test(path)},
                    )
                )
    return findings


def _looks_like_test(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    return any(p in parts for p in ("tests", "test", "fixtures", "examples", "example"))


def _refs_for(rule_id: str) -> list[str]:
    if rule_id.startswith("static.shell.exfil") or "egress" in rule_id:
        return ["OWASP-MCP-T07-data-exfil", "MITRE-ATLAS-AML.T0048"]
    if "pickle" in rule_id:
        return ["CWE-502"]
    if "eval" in rule_id or "system" in rule_id or "shell_true" in rule_id:
        return ["CWE-78", "CWE-94"]
    if "ssh" in rule_id or "aws_creds" in rule_id or "git_credential" in rule_id:
        return ["OWASP-MCP-T05-credential-exfil"]
    return []
