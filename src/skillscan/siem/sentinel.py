"""Microsoft Sentinel formatter — Log Analytics custom log shape.

Sentinel ingest expects a JSON array of records to a custom log table
(name configured per-deployment). Auth uses an HMAC over the body in
Sentinel's native client; this module emits the *payload* and leaves
auth to the proxy / Logic App that actually does the POST.
"""

from __future__ import annotations

from typing import Any

from skillscan.models import ScanResult


def to_sentinel(result: ScanResult, *, host_id: str | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for f in result.findings:
        rows.append({
            "TimeGenerated": None,  # ingest stamps when omitted
            "Host_s": host_id or "skillscan",
            "RuleId_s": f.rule_id,
            "Category_s": f.category,
            "Severity_s": f.severity,
            "Confidence_s": f.confidence,
            "Summary_s": f.summary,
            "ArtifactKind_s": f.artifact.kind.value,
            "ArtifactHost_s": f.artifact.host.value,
            "ArtifactName_s": f.artifact.name,
            "ArtifactPath_s": str(f.artifact.path),
            "FilePath_s": str(f.file) if f.file else None,
            "Line_d": f.line,
            "Evidence_s": "\n".join(f.evidence) if f.evidence else None,
            "References_s": ",".join(f.references) if f.references else None,
            "Metadata_s": str(f.metadata) if f.metadata else None,
        })
    return rows
