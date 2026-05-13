"""Microsoft Teams incoming-webhook alert.

POST <webhook_url> with an Adaptive Card payload (Teams' native format).
Threshold gating + per-finding card sections mirror the Slack
implementation so the two stay in lockstep.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections import Counter

from skillscan.models import Finding, ScanResult


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEV_COLOR = {"critical": "Attention", "high": "Warning", "medium": "Warning", "low": "Default", "info": "Default"}


def build_teams_payload(result: ScanResult, *, threshold: str = "high", host_id: str | None = None) -> dict:
    findings = _filter(result.findings, threshold)
    if not findings:
        return {}
    counts = Counter(f.severity for f in findings)
    title = f"skills-scanner — {len(findings)} finding(s) at ≥ {threshold}"
    if host_id:
        title += f" on {host_id}"
    summary_facts = [
        {"title": s, "value": str(counts.get(s, 0))}
        for s in ("critical", "high", "medium", "low", "info")
        if counts.get(s)
    ]
    body = [
        {"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": title},
        {"type": "FactSet", "facts": summary_facts},
    ]
    for f in findings[:8]:
        body.append({
            "type": "Container",
            "style": _SEV_COLOR.get(f.severity, "Default"),
            "items": [
                {"type": "TextBlock", "weight": "Bolder", "text": f"{f.severity.upper()} · {f.rule_id}", "wrap": True},
                {"type": "TextBlock", "text": _truncate(f.summary, 240), "wrap": True},
                {"type": "TextBlock", "isSubtle": True,
                 "text": f"artifact: {f.artifact.name} · file: {f.file or f.artifact.path}", "wrap": True},
            ],
        })
    if len(findings) > 8:
        body.append({"type": "TextBlock", "isSubtle": True, "text": f"+{len(findings) - 8} more findings — see scan output", "wrap": True})

    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "https://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                },
            }
        ],
    }


def send_teams(
    webhook_url: str,
    result: ScanResult,
    *,
    threshold: str = "high",
    host_id: str | None = None,
    requester=None,
) -> int:
    payload = build_teams_payload(result, threshold=threshold, host_id=host_id)
    if not payload:
        return 0
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "skillscan-alert"}
    if requester is not None:
        requester(webhook_url, body, headers)
    else:
        request = urllib.request.Request(webhook_url, data=body, headers=headers, method="POST")
        try:
            urllib.request.urlopen(request, timeout=15).close()  # noqa: S310
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Teams alert post failed: {exc}") from exc
    finding_count = len(payload["attachments"][0]["content"]["body"]) - 2
    return max(0, finding_count)


# --------------------------------------------------------------------------- #

def _filter(findings: list[Finding], threshold: str) -> list[Finding]:
    rank = _SEV_RANK.get(threshold, 3)
    return sorted(
        [f for f in findings if _SEV_RANK.get(f.severity, 0) >= rank],
        key=lambda f: _SEV_RANK.get(f.severity, 0),
        reverse=True,
    )


def _truncate(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"
