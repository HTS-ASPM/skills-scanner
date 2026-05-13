"""Marketplace reputation enrichment.

Looks up discovered skills against a curated list of known-bad
signatures + descriptions sourced from the public agent-skills
incident reporting (Snyk ToxicSkills, OpenClaw / VirusTotal advisories,
Trojan's Whisper academic study).

The default registry ships with the package; deployers can supply an
override JSON via SKILLSCAN_REPUTATION_REGISTRY (env var) for fleet-
specific intel.
"""

from skillscan.marketplace.reputation import (
    DEFAULT_REGISTRY,
    ReputationVerdict,
    enrich_with_reputation,
    load_registry,
)

__all__ = ["DEFAULT_REGISTRY", "ReputationVerdict", "enrich_with_reputation", "load_registry"]
