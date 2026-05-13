"""Deep static analysis of bundled Python files using the ast module.

Why a second layer when rules.static already covers this surface:
the regex layer catches one-line patterns. The AST layer catches:

  - subprocess.run(..., shell=True) when the call is split across lines
    or assembled from variables
  - dynamic imports (importlib, __import__) of dangerous modules
  - eval/exec on a NAME (variable) rather than a literal string
  - requests/httpx posts whose URL is built by string concatenation
  - dangerous module imports we never want to see in a skill
    (pickle, marshal, ctypes, code, types.FunctionType etc.)
  - obfuscated decoders (base64.b64decode followed by exec/compile)

Findings here are higher confidence than the regex layer because the
match is structural, not lexical.
"""

from __future__ import annotations

import ast
from pathlib import Path

from skillscan.models import Artifact, ArtifactKind, Finding


_DANGEROUS_MODULES = {
    "pickle", "cPickle", "_pickle", "marshal", "shelve",
    "ctypes", "code", "compile",
}


_NETWORK_MODULES = {"requests", "httpx", "urllib", "urllib2", "aiohttp", "socket"}


def _candidate_files(artifact: Artifact) -> list[Path]:
    files: list[Path] = []
    for p in artifact.bundled_files:
        if p.suffix.lower() == ".py" and p.is_file():
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
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError:
            continue
        visitor = _DeepVisitor(path, artifact)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    return findings


class _DeepVisitor(ast.NodeVisitor):
    def __init__(self, path: Path, artifact: Artifact):
        self.path = path
        self.artifact = artifact
        self.findings: list[Finding] = []
        self.last_b64_decode_line: int | None = None

    # ----------- imports -----------
    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802 (ast API)
        for alias in node.names:
            top = alias.name.split(".")[0]
            if top in _DANGEROUS_MODULES:
                self._emit(
                    "deep.import_dangerous",
                    f"Skill bundle imports dangerous module `{alias.name}` (deserialization / native code)",
                    severity="high",
                    line=node.lineno,
                    evidence=[alias.name],
                    metadata={"module": alias.name},
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.module and node.module.split(".")[0] in _DANGEROUS_MODULES:
            for alias in node.names:
                self._emit(
                    "deep.import_dangerous",
                    f"Skill bundle imports `{node.module}.{alias.name}` (deserialization / native code)",
                    severity="high",
                    line=node.lineno,
                    evidence=[f"{node.module}.{alias.name}"],
                    metadata={"module": node.module, "name": alias.name},
                )
        self.generic_visit(node)

    # ----------- calls -----------
    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        callee = _attr_path(node.func)
        if callee == "subprocess.run" or callee == "subprocess.Popen" or callee == "subprocess.call":
            if any(self._kw_is_truthy(kw, "shell") for kw in node.keywords):
                self._emit(
                    "deep.subprocess_shell_true",
                    f"`{callee}(..., shell=True)` (AST-confirmed)",
                    severity="high",
                    line=node.lineno,
                    evidence=[callee],
                )

        if callee in {"eval", "exec"}:
            arg_repr = _arg_repr(node.args[0]) if node.args else "<no-arg>"
            severity = "high" if not _is_str_literal(node.args[0] if node.args else None) else "medium"
            self._emit(
                "deep.eval_exec",
                f"`{callee}({arg_repr})` (AST-confirmed)",
                severity=severity,
                line=node.lineno,
                evidence=[callee, arg_repr[:80]],
                metadata={"arg_type": type(node.args[0]).__name__ if node.args else None},
            )

        if callee in {"importlib.import_module", "__import__"}:
            arg_repr = _arg_repr(node.args[0]) if node.args else "<no-arg>"
            self._emit(
                "deep.dynamic_import",
                f"Dynamic import via `{callee}({arg_repr})` — module name not statically resolvable",
                severity="medium",
                line=node.lineno,
                evidence=[callee, arg_repr[:80]],
            )

        if callee == "base64.b64decode":
            self.last_b64_decode_line = node.lineno

        # base64.b64decode(...) followed within 3 lines by exec/eval/compile
        if callee in {"exec", "eval", "compile"} and self.last_b64_decode_line is not None:
            if 0 <= node.lineno - self.last_b64_decode_line <= 3:
                self._emit(
                    "deep.b64_then_exec",
                    f"base64 decode followed by `{callee}` within 3 lines — classic obfuscated payload pattern",
                    severity="critical",
                    line=node.lineno,
                    evidence=[f"b64@L{self.last_b64_decode_line}", f"{callee}@L{node.lineno}"],
                )

        # requests/httpx POST with non-literal URL
        if (
            callee.endswith(".post") or callee.endswith(".put") or callee.endswith(".patch")
        ) and node.args:
            url_arg = node.args[0]
            if not _is_str_literal(url_arg) and _looks_like_http_call(callee):
                self._emit(
                    "deep.http_call_dynamic_url",
                    f"`{callee}(<dynamic-url>, ...)` — URL not a string literal, harder to allowlist",
                    severity="medium",
                    line=node.lineno,
                    evidence=[callee, type(url_arg).__name__],
                )

        self.generic_visit(node)

    # ----------- helpers -----------
    def _kw_is_truthy(self, kw: ast.keyword, name: str) -> bool:
        if kw.arg != name:
            return False
        v = kw.value
        if isinstance(v, ast.Constant):
            return bool(v.value)
        return True  # non-literal => assume truthy (safe default)

    def _emit(
        self,
        rule_id: str,
        summary: str,
        *,
        severity: str,
        line: int,
        evidence: list[str],
        metadata: dict | None = None,
    ) -> None:
        self.findings.append(
            Finding(
                rule_id=rule_id,
                category="static",
                severity=severity,
                confidence="high",
                summary=summary,
                artifact=self.artifact,
                file=self.path,
                line=line,
                evidence=evidence,
                references=_refs_for(rule_id),
                metadata=metadata or {},
            )
        )


def _attr_path(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_attr_path(node.value)}.{node.attr}"
    return ""


def _arg_repr(node: ast.AST | None) -> str:
    if node is None:
        return "<none>"
    if isinstance(node, ast.Constant):
        return repr(node.value)
    if isinstance(node, ast.Name):
        return node.id
    return ast.dump(node)[:120]


def _is_str_literal(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _looks_like_http_call(callee: str) -> bool:
    head = callee.split(".")[0]
    return head in _NETWORK_MODULES or head in {"http", "client"}


def _refs_for(rule_id: str) -> list[str]:
    table = {
        "deep.import_dangerous": ["CWE-502", "OWASP-MCP-T03-supply-chain"],
        "deep.subprocess_shell_true": ["CWE-78", "CWE-77"],
        "deep.eval_exec": ["CWE-94"],
        "deep.dynamic_import": ["CWE-829"],
        "deep.b64_then_exec": ["CWE-506", "MITRE-ATLAS-AML.T0011"],
        "deep.http_call_dynamic_url": ["CWE-918"],
    }
    return table.get(rule_id, [])
