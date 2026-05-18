"""PagerDuty Events API v2 alert connector.

POST https://events.pagerduty.com/v2/enqueue with:
  {"routing_key": <integration key>,
   "event_action": "trigger",
   "payload": {"summary": ..., "severity": ..., "source": ..., ...},
   "dedup_key": <stable string per host+threshold>}

Severity mapping (PagerDuty accepts: critical, error, warning, info):
  critical -> critical
  high     -> error
  medium   -> warning
  low      -> info
  info     -> info

Routing key is read from PAGERDUTY_ROUTING_KEY (override via --pd-key-env).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections import Counter

from skillscan.models import ScanResult


_API_URL = "https://events.pagerduty.com/v2/enqueue"

_SEV_MAP = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
    "info": "info",
}

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def build_pagerduty_payload(
    result: ScanResult,
    *,
    routing_key: str,
    threshold: str = "high",
    host_id: str | None = None,
    dedup_key: str | None = None,
) -> dict | None:
    findings = _filter(result.findings, threshold)
    if not findings:
        return None
    counts = Counter(f.severity for f in findings)
    top_severity = max(counts, key=lambda k: _SEV_RANK[k])
    pd_severity = _SEV_MAP.get(top_severity, "warning")
    summary = (
        f"skills-scanner: {len(findings)} finding(s) ≥ {threshold}"
        + (f" on {host_id}" if host_id else "")
    )
    return {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": dedup_key or _default_dedup(host_id, threshold),
        "payload": {
            "summary": summary,
            "severity": pd_severity,
            "source": host_id or "skills-scanner",
            "component": "ai-skills",
            "group": "aspm",
            "class": top_severity,
            "custom_details": {
                "counts": dict(counts),
                "top_findings": [
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "artifact": f.artifact.name,
                        "summary": f.summary[:240],
                    }
                    for f in findings[:8]
                ],
            },
        },
    }


def send_pagerduty(
    result: ScanResult,
    *,
    key_env: str = "PAGERDUTY_ROUTING_KEY",
    threshold: str = "high",
    host_id: str | None = None,
    dedup_key: str | None = None,
    requester=None,
) -> int:
    routing_key = os.environ.get(key_env)
    if not routing_key:
        raise RuntimeError(f"missing PagerDuty routing key in env {key_env}")
    payload = build_pagerduty_payload(
        result, routing_key=routing_key,
        threshold=threshold, host_id=host_id, dedup_key=dedup_key,
    )
    if not payload:
        return 0
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "skillscan-pd"}
    if requester is not None:
        requester(_API_URL, body, headers)
    else:
        request = urllib.request.Request(_API_URL, data=body, headers=headers, method="POST")
        try:
            urllib.request.urlopen(request, timeout=15).close()  # noqa: S310
        except urllib.error.URLError as exc:
            raise RuntimeError(f"PagerDuty enqueue failed: {exc}") from exc
    return len(payload["payload"]["custom_details"]["top_findings"])


# --------------------------------------------------------------------------- #

def _filter(findings, threshold):
    rank = _SEV_RANK.get(threshold, 3)
    return sorted(
        [f for f in findings if _SEV_RANK.get(f.severity, 0) >= rank],
        key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True,
    )


def _default_dedup(host_id: str | None, threshold: str) -> str:
    return f"skillscan/{host_id or 'unknown-host'}/{threshold}"
