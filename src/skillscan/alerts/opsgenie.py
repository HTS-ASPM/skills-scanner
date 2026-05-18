"""Opsgenie alert connector.

POST https://api.opsgenie.com/v2/alerts with:
  Authorization: GenieKey <api-key>
  body: {"message": ..., "priority": ..., "tags": [...], "details": {...}}

Priority mapping (Opsgenie accepts P1..P5):
  critical -> P1
  high     -> P2
  medium   -> P3
  low      -> P4
  info     -> P5

API key is read from OPSGENIE_API_KEY (override via --opsgenie-key-env).
EU region: pass --opsgenie-api-base https://api.eu.opsgenie.com.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections import Counter

from skillscan.models import ScanResult


_DEFAULT_API_BASE = "https://api.opsgenie.com"

_PRIORITY_MAP = {
    "critical": "P1",
    "high":     "P2",
    "medium":   "P3",
    "low":      "P4",
    "info":     "P5",
}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def build_opsgenie_payload(
    result: ScanResult,
    *,
    threshold: str = "high",
    host_id: str | None = None,
    alias: str | None = None,
) -> dict | None:
    findings = _filter(result.findings, threshold)
    if not findings:
        return None
    counts = Counter(f.severity for f in findings)
    top = max(counts, key=lambda k: _SEV_RANK[k])
    message = (
        f"skills-scanner: {len(findings)} finding(s) ≥ {threshold}"
        + (f" on {host_id}" if host_id else "")
    )
    return {
        "message": message,
        "alias": alias or _default_alias(host_id, threshold),
        "priority": _PRIORITY_MAP.get(top, "P3"),
        "tags": sorted({"skillscan", f"sev:{top}", *(f"sev:{s}" for s in counts.keys())}),
        "source": host_id or "skills-scanner",
        "entity": host_id or "skills-scanner",
        "details": {
            **{f"count_{k}": str(v) for k, v in counts.items()},
            "top_rule": findings[0].rule_id,
            "top_artifact": findings[0].artifact.name,
        },
        "description": _description(findings),
    }


def send_opsgenie(
    result: ScanResult,
    *,
    key_env: str = "OPSGENIE_API_KEY",
    api_base: str = _DEFAULT_API_BASE,
    threshold: str = "high",
    host_id: str | None = None,
    alias: str | None = None,
    requester=None,
) -> int:
    api_key = os.environ.get(key_env)
    if not api_key:
        raise RuntimeError(f"missing Opsgenie API key in env {key_env}")
    payload = build_opsgenie_payload(
        result, threshold=threshold, host_id=host_id, alias=alias,
    )
    if not payload:
        return 0
    url = api_base.rstrip("/") + "/v2/alerts"
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"GenieKey {api_key}",
        "User-Agent": "skillscan-opsgenie",
    }
    if requester is not None:
        requester(url, body, headers)
    else:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            urllib.request.urlopen(request, timeout=15).close()  # noqa: S310
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Opsgenie alert post failed: {exc}") from exc
    return len(payload["tags"])


# --------------------------------------------------------------------------- #

def _filter(findings, threshold):
    rank = _SEV_RANK.get(threshold, 3)
    return sorted(
        [f for f in findings if _SEV_RANK.get(f.severity, 0) >= rank],
        key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True,
    )


def _default_alias(host_id: str | None, threshold: str) -> str:
    return f"skillscan-{host_id or 'unknown'}-{threshold}"


def _description(findings) -> str:
    out = []
    for f in findings[:8]:
        out.append(f"- [{f.severity.upper()}] {f.rule_id} on {f.artifact.name}: {f.summary[:160]}")
    return "\n".join(out)
