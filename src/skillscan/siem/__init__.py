"""SIEM payload formatters — Splunk HEC, Elastic ECS, Microsoft Sentinel.

Each formatter takes a ScanResult and returns a payload shape the
upstream collector accepts directly. Wire them via the fleet agent's
--siem flag.
"""

from __future__ import annotations

from skillscan.models import ScanResult
from skillscan.siem.elastic import to_elastic_ecs
from skillscan.siem.sentinel import to_sentinel
from skillscan.siem.splunk import to_splunk_hec


def format_for_siem(result: ScanResult, fmt: str, *, host_id: str | None = None):
    fmt = (fmt or "").lower()
    if fmt == "splunk":
        return to_splunk_hec(result, host_id=host_id)
    if fmt == "elastic":
        return to_elastic_ecs(result, host_id=host_id)
    if fmt == "sentinel":
        return to_sentinel(result, host_id=host_id)
    raise ValueError(f"unknown SIEM format: {fmt!r}")


__all__ = [
    "format_for_siem",
    "to_splunk_hec",
    "to_elastic_ecs",
    "to_sentinel",
]
