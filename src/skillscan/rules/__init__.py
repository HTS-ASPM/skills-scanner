"""Rule layer: applies detectors to discovered artifacts.

Phase S0 ships the discovery + parsers only; rules land in S1.
This package exists so downstream code can already import from a stable path.
"""

from skillscan.models import Artifact, Finding


def run_rules(artifacts: list[Artifact]) -> list[Finding]:
    """No rules wired yet — placeholder for the S1 rule engine."""
    return []
