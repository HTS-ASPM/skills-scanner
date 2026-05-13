"""JS / TS deep scan — regex-based, since pure-Python JS AST parsing
adds a heavy dep (esprima / pyjsparser are slow + unmaintained).

Targets the same risk classes as the Python AST layer:

  deep.js.eval_or_function       eval(...) / new Function(...)
  deep.js.child_process_exec     child_process.exec / execSync /
                                 spawnSync with shell:true
  deep.js.dynamic_require        require(<dynamic>)
  deep.js.fetch_dynamic_url      fetch / axios with template-literal URL
  deep.js.buffer_b64_then_eval   Buffer.from(..., 'base64') near eval

Skill bundles increasingly ship JS/TS (Node MCP servers, Cursor /
Windsurf rules with attached helpers); regex is the pragmatic choice.
"""

from __future__ import annotations

import re
from pathlib import Path

from skillscan.models import Artifact, ArtifactKind, Finding


_RULES: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("deep.js.eval_or_function", "eval() or `new Function(...)` in JS skill code", "high",
     re.compile(r"\b(eval|Function)\s*\(", re.IGNORECASE)),

    ("deep.js.child_process_exec",
     "child_process exec / execSync / spawn with shell:true",
     "high",
     re.compile(
         r"child_process\.(exec(?:Sync)?|spawn(?:Sync)?)\s*\("
         r"|require\s*\(\s*['\"]child_process['\"]\s*\)"
         r"|from\s+['\"]child_process['\"]"
         r"|import\s*\(\s*['\"]child_process['\"]\s*\)",
         re.IGNORECASE,
     )),

    ("deep.js.dynamic_require", "Dynamic require(<expr>)", "medium",
     re.compile(r"require\s*\(\s*[^'\")]+\)", re.IGNORECASE)),

    ("deep.js.fetch_dynamic_url",
     "fetch / axios call with template-literal URL", "medium",
     re.compile(
         r"(fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*`[^`]*\$\{",
         re.IGNORECASE,
     )),

    ("deep.js.buffer_b64_then_eval",
     "Buffer.from(..., 'base64') decoded value then eval'd",
     "critical",
     re.compile(
         r"Buffer\.from\([^)]*['\"]base64['\"][^)]*\).*?(eval|new Function)\s*\(",
         re.IGNORECASE | re.DOTALL,
     )),
]


_JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


def _candidate_files(artifact: Artifact) -> list[Path]:
    return [
        p for p in artifact.bundled_files
        if p.suffix.lower() in _JS_SUFFIXES and p.is_file()
    ]


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
        for rule_id, summary, severity, pattern in _RULES:
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
                        metadata={"language": "javascript"},
                    )
                )
    return findings


def _refs_for(rule_id: str) -> list[str]:
    table = {
        "deep.js.eval_or_function": ["CWE-94"],
        "deep.js.child_process_exec": ["CWE-78", "CWE-77"],
        "deep.js.dynamic_require": ["CWE-829"],
        "deep.js.fetch_dynamic_url": ["CWE-918"],
        "deep.js.buffer_b64_then_eval": ["CWE-506", "MITRE-ATLAS-AML.T0011"],
    }
    return table.get(rule_id, [])
