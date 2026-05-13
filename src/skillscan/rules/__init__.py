"""Rule layer: dispatches every artifact through every applicable rule module.

Phase S1 ships five rule modules. Each exports a `run(artifact) -> list[Finding]`.
Adding a new module is just appending to `_MODULES` below.
"""

from __future__ import annotations

from skillscan.models import Artifact, Finding
from skillscan.rules import frontmatter, hidden, mcp, secrets, static


_MODULES = [frontmatter, hidden, secrets, static, mcp]


def run_rules(artifacts: list[Artifact]) -> list[Finding]:
    findings: list[Finding] = []
    for artifact in artifacts:
        for module in _MODULES:
            findings.extend(module.run(artifact))
    return findings
