"""Rule layer: dispatches every artifact through every applicable rule module.

S1: frontmatter + hidden + secrets + static + mcp (per-artifact)
S2: capability (per-artifact) + drift (cross-scan, separate entry) +
    nl_judge (optional, per-artifact, gated)
S3: deep_scan (per-artifact, AST-based)

Adding a new per-artifact module is just appending to `_MODULES` below.
"""

from __future__ import annotations

from skillscan.models import Artifact, Finding
from skillscan.rules import (
    capability,
    deep_scan,
    frontmatter,
    hidden,
    mcp,
    nl_judge,
    secrets,
    static,
)


_MODULES = [frontmatter, hidden, secrets, static, mcp, capability, deep_scan]


def run_rules(artifacts: list[Artifact], *, with_judge: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    for artifact in artifacts:
        for module in _MODULES:
            findings.extend(module.run(artifact))
        if with_judge and nl_judge.is_available():
            findings.extend(nl_judge.run(artifact))
    return findings
