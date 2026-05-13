"""Splunk HEC formatter — one event per finding.

POST <splunk_hec>/services/collector with `Authorization: Splunk <token>`.
The body is a newline-delimited stream of HEC-shaped events, but for
batched ingest a JSON array also works against modern HEC builds.
We emit a JSON array for simplicity.
"""

from __future__ import annotations

from typing import Any

from skillscan.models import ScanResult


def to_splunk_hec(result: ScanResult, *, host_id: str | None = None) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for f in result.findings:
        events.append({
            "sourcetype": "skillscan:finding",
            "host": host_id or "skillscan",
            "source": "skillscan",
            "event": {
                "rule_id": f.rule_id,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "summary": f.summary,
                "artifact": {
                    "kind": f.artifact.kind.value,
                    "host": f.artifact.host.value,
                    "name": f.artifact.name,
                    "path": str(f.artifact.path),
                },
                "file": str(f.file) if f.file else None,
                "line": f.line,
                "evidence": f.evidence,
                "references": f.references,
                "metadata": f.metadata,
            },
        })
    return events
