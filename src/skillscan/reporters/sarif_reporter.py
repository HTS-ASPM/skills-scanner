"""SARIF 2.1.0 reporter for skills-scanner findings — drops into IDEs
and PR-annotation tooling out of the box.
"""

from __future__ import annotations

import json

from skillscan import __version__
from skillscan.models import Finding, ScanResult


_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}


def to_sarif(result: ScanResult) -> str:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for finding in result.findings:
        if finding.rule_id not in rules:
            rules[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": finding.summary[:120]},
                "fullDescription": {"text": finding.summary},
                "properties": {
                    "category": finding.category,
                    "references": finding.references,
                },
            }
        results.append(_result_for(finding))
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "skills-scanner",
                        "version": __version__,
                        "informationUri": "https://github.com/HTS-ASPM/skills-scanner",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2)


def _result_for(finding: Finding) -> dict:
    location: dict = {"artifactLocation": {"uri": str(finding.file or finding.artifact.path)}}
    if finding.line:
        location["region"] = {"startLine": finding.line}
    return {
        "ruleId": finding.rule_id,
        "level": _LEVEL_MAP.get(finding.severity, "warning"),
        "message": {"text": finding.summary},
        "locations": [{"physicalLocation": location}],
        "properties": {
            "severity": finding.severity,
            "confidence": finding.confidence,
            "category": finding.category,
            "artifactKind": finding.artifact.kind.value,
            "host": finding.artifact.host.value,
            "evidence": finding.evidence,
            "references": finding.references,
            "metadata": finding.metadata,
        },
    }
