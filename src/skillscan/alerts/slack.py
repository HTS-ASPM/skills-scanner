"""Slack incoming-webhook alert.

POST <webhook_url> with the standard Slack message JSON shape.
Threshold filter applied before formatting so we never POST an empty
alert. Returns the count of findings included.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections import Counter

from skillscan.models import Finding, ScanResult


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEV_EMOJI = {"critical": ":rotating_light:", "high": ":warning:", "medium": ":heavy_exclamation_mark:", "low": ":information_source:", "info": ":speech_balloon:"}


def build_slack_payload(result: ScanResult, *, threshold: str = "high", host_id: str | None = None) -> dict:
    findings = _filter(result.findings, threshold)
    counts = Counter(f.severity for f in findings)
    if not findings:
        return {}
    header = f"skills-scanner :mag: {len(findings)} finding(s) at >= {threshold}"
    if host_id:
        header += f" on `{host_id}`"
    summary_line = " · ".join(f"{_SEV_EMOJI.get(s, '')} *{s}*: {c}" for s, c in sorted(counts.items(), key=lambda kv: -_SEV_RANK[kv[0]]))
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": header}},
        {"type": "section", "text": {"type": "mrkdwn", "text": summary_line}},
    ]
    for f in findings[:8]:  # cap detail rows so we don't spam channel
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{_SEV_EMOJI.get(f.severity, '')} *{f.severity.upper()}* `{f.rule_id}`\n"
                    f"_{_truncate(f.summary, 240)}_\n"
                    f"artifact: `{f.artifact.name}` · file: `{f.file or f.artifact.path}`"
                ),
            },
        })
    if len(findings) > 8:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"_+{len(findings) - 8} more findings — see scan output_"}]})
    return {"blocks": blocks, "text": header}


def send_slack(
    webhook_url: str,
    result: ScanResult,
    *,
    threshold: str = "high",
    host_id: str | None = None,
    requester=None,
) -> int:
    payload = build_slack_payload(result, threshold=threshold, host_id=host_id)
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
            raise RuntimeError(f"Slack alert post failed: {exc}") from exc
    return len(payload.get("blocks", [])) - 2  # detail rows


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
