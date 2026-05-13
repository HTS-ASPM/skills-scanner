"""HTTP poster used by the fleet agent.

Sends two payloads, both pure stdlib (urllib):

  1. ASPM ingest — JSON ScanResult with optional X-Skillscan-Host
     and Bearer auth from a named env var.
  2. (optional) SIEM mirror — Splunk HEC / Elastic ECS / Sentinel
     formatted findings to a separate URL. Auth per format follows the
     vendor convention (Splunk: 'Authorization: Splunk <token>',
     Elastic: 'Authorization: ApiKey <key>', Sentinel: workspace+key).

Auth values are read from named env vars per format so credentials
never touch argv or telemetry.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from skillscan.models import ScanResult
from skillscan.reporters import to_json
from skillscan.siem import format_for_siem


class PostError(RuntimeError):
    pass


def post_findings(
    *,
    url: str,
    result: ScanResult,
    token_env: str = "ASPM_TOKEN",
    host_id: str | None = None,
    siem_format: str | None = None,
    siem_url: str | None = None,
    requester=None,  # injected for tests: callable(url, body, headers) -> dict
) -> dict:
    """Post ScanResult to ASPM, then optionally mirror to SIEM."""
    # Primary: ASPM ingest
    aspm_response = _post_json(
        url,
        json.loads(to_json(result)),
        headers=_aspm_headers(token_env, host_id),
        requester=requester,
    )
    response: dict = {"aspm": aspm_response}

    if siem_format and siem_url:
        siem_payload = format_for_siem(result, siem_format, host_id=host_id)
        response["siem"] = _post_json(
            siem_url,
            siem_payload,
            headers=_siem_headers(siem_format),
            requester=requester,
        )
    return response


def _aspm_headers(token_env: str, host_id: str | None) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "skillscan-fleet-agent",
    }
    token = os.environ.get(token_env)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if host_id:
        headers["X-Skillscan-Host"] = host_id
    return headers


def _siem_headers(siem_format: str) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "User-Agent": "skillscan-siem"}
    fmt = siem_format.lower()
    if fmt == "splunk":
        token = os.environ.get("SPLUNK_HEC_TOKEN")
        if token:
            headers["Authorization"] = f"Splunk {token}"
    elif fmt == "elastic":
        api_key = os.environ.get("ELASTIC_API_KEY")
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"
    elif fmt == "sentinel":
        # Sentinel ingest uses HMAC over the body — out of scope here. Accept
        # a pre-computed shared secret as a Bearer for a workload-identity
        # scenario; the deployer is expected to wrap with a Sentinel proxy.
        token = os.environ.get("SENTINEL_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    return headers


def _post_json(url: str, payload, *, headers: dict[str, str], requester) -> dict:
    body = json.dumps(payload).encode("utf-8")
    if requester is not None:
        return requester(url, body, headers)
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:  # noqa: S310
            text = resp.read().decode("utf-8", errors="replace")
            return {"status": resp.status, "body": text}
    except urllib.error.HTTPError as exc:
        raise PostError(f"post to {url} failed: {exc.code} {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise PostError(f"post to {url} failed: {exc.reason}") from exc
