"""Drift / rug-pull rule: produces Finding objects from store.DriftSignal.

Run separately from the per-artifact rule loop because drift is a
cross-scan signal — the rule engine receives the diff once.
"""

from __future__ import annotations

from skillscan.models import Finding
from skillscan.store import DriftSignal


_KIND_TO_SEVERITY = {
    "rug-pull": "critical",
    "scope-change": "medium",
    "new-artifact": "low",
    "removed": "info",
}


_KIND_TO_RULE_ID = {
    "rug-pull": "drift.rug_pull",
    "scope-change": "drift.scope_change",
    "new-artifact": "drift.new_artifact",
    "removed": "drift.removed",
}


def findings_for_drift(signals: list[DriftSignal]) -> list[Finding]:
    findings: list[Finding] = []
    for sig in signals:
        rule_id = _KIND_TO_RULE_ID.get(sig.kind, "drift.unknown")
        severity = _KIND_TO_SEVERITY.get(sig.kind, "low")
        findings.append(
            Finding(
                rule_id=rule_id,
                category="drift",
                severity=severity,
                confidence="high",
                summary=sig.summary,
                artifact=sig.artifact,
                file=sig.artifact.path,
                line=None,
                evidence=[],
                references=(
                    ["OWASP-MCP-T03-supply-chain", "OWASP-LLM05-supply-chain"]
                    if sig.kind == "rug-pull"
                    else ["OWASP-LLM05-supply-chain"]
                ),
                metadata={"previous": sig.previous, "current": sig.current, "drift_kind": sig.kind},
            )
        )
    return findings
