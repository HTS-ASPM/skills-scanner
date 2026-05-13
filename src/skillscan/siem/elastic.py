"""Elastic ECS-shaped formatter for skillscan findings.

Maps to the Elastic Common Schema (ECS) so events drop into existing
Kibana dashboards / detection rules without remapping. Severity is
emitted as `event.severity` (1-100 scale per ECS) and the original
severity label as `event.risk_score_norm`.
"""

from __future__ import annotations

from typing import Any

from skillscan.models import ScanResult


_SEVERITY_NUMERIC = {"critical": 80, "high": 60, "medium": 40, "low": 20, "info": 10}


def to_elastic_ecs(result: ScanResult, *, host_id: str | None = None) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for f in result.findings:
        events.append({
            "@timestamp": None,  # ingest pipeline can stamp
            "host": {"name": host_id or "skillscan"},
            "agent": {"name": "skillscan", "type": "scanner", "version": "0.1.0"},
            "event": {
                "kind": "alert",
                "category": ["intrusion_detection"],
                "type": ["info"],
                "severity": _SEVERITY_NUMERIC.get(f.severity, 10),
                "risk_score_norm": f.severity,
                "module": "skillscan",
                "dataset": "skillscan.finding",
                "outcome": "unknown",
            },
            "rule": {
                "id": f.rule_id,
                "name": f.summary[:120],
                "category": f.category,
                "ruleset": "skillscan",
                "reference": f.references,
            },
            "file": {"path": str(f.file)} if f.file else None,
            "skillscan": {
                "artifact_kind": f.artifact.kind.value,
                "artifact_host": f.artifact.host.value,
                "artifact_name": f.artifact.name,
                "artifact_path": str(f.artifact.path),
                "evidence": f.evidence,
                "metadata": f.metadata,
                "line": f.line,
                "confidence": f.confidence,
            },
        })
    return events
