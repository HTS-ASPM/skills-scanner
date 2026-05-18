"""Incident timeline view.

Builds a chronological "what happened when" list from:
  - drift findings (drift.{rug_pull,scope_change,new_artifact,removed})
    drawn from the SQLite baseline store (timestamped scans)
  - collusion findings (treated as a single point at scan time —
    they're cross-scan signals)
  - critical / high findings (point-in-time at the current scan)

Outputs a self-contained HTML fragment ready to embed in the dashboard.
"""

from __future__ import annotations

import html
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skillscan.models import Finding, ScanResult


@dataclass(frozen=True)
class TimelineEvent:
    timestamp_unix: int
    kind: str                  # drift | collusion | critical | scan
    severity: str
    title: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp_unix": self.timestamp_unix,
            "kind": self.kind,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
        }


def build_timeline(result: ScanResult, baseline_db: Path | None = None, scan_root: str | None = None) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    now = int(datetime.now(timezone.utc).timestamp())

    # 1. Baseline scan history (if available).
    if baseline_db and scan_root:
        events.extend(_scans_from_db(baseline_db, scan_root))

    # 2. Drift + collusion findings get the current scan's timestamp.
    for f in result.findings:
        if f.category == "drift":
            events.append(TimelineEvent(
                timestamp_unix=now,
                kind="drift",
                severity=f.severity,
                title=f"Drift: {f.artifact.name}",
                detail=f.summary,
            ))
        elif f.category == "collusion":
            events.append(TimelineEvent(
                timestamp_unix=now,
                kind="collusion",
                severity=f.severity,
                title=f"Collusion: {f.rule_id}",
                detail=f.summary,
            ))
        elif f.severity in {"critical", "high"}:
            events.append(TimelineEvent(
                timestamp_unix=now,
                kind="critical",
                severity=f.severity,
                title=f"{f.severity.upper()}: {f.rule_id}",
                detail=f"{f.artifact.name} — {f.summary[:160]}",
            ))

    # Newest first.
    events.sort(key=lambda e: e.timestamp_unix, reverse=True)
    return events


def render_timeline_html(events: list[TimelineEvent]) -> str:
    if not events:
        return "<div class='ss-timeline empty'><p><em>No incidents recorded.</em></p></div>"
    rows: list[str] = ["<ol class='ss-timeline'>"]
    for ev in events:
        ts = datetime.fromtimestamp(ev.timestamp_unix, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
        rows.append(
            f"<li class='ss-event kind-{html.escape(ev.kind)} sev-{html.escape(ev.severity)}'>"
            f"<span class='ts'>{ts}</span>"
            f"<span class='kind'>{html.escape(ev.kind)}</span>"
            f"<span class='sev'>{html.escape(ev.severity)}</span>"
            f"<span class='title'>{html.escape(ev.title)}</span>"
            f"<span class='detail'>{html.escape(ev.detail)}</span>"
            "</li>"
        )
    rows.append("</ol>")
    rows.append(_TIMELINE_CSS)
    return "".join(rows)


# --------------------------------------------------------------------------- #

def _scans_from_db(db_path: Path, scan_root: str) -> list[TimelineEvent]:
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(str(db_path))
    except sqlite3.OperationalError:
        return []
    try:
        with closing(conn.cursor()) as cur:
            cur.execute(
                "SELECT created_at, artifact_count FROM scans WHERE scan_root=? ORDER BY created_at DESC LIMIT 25",
                (scan_root,),
            )
            rows = cur.fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()
    return [
        TimelineEvent(
            timestamp_unix=int(ts),
            kind="scan",
            severity="info",
            title=f"Baseline saved ({count} artifacts)",
            detail=f"scan_root={scan_root}",
        )
        for ts, count in rows
    ]


_TIMELINE_CSS = """<style>
  .ss-timeline { list-style: none; padding: 0; margin: 0; border-left: 2px solid #ddd; }
  .ss-timeline li { padding: 0.5em 0.8em; margin-left: -1px; border-left: 2px solid transparent; display: grid;
                    grid-template-columns: 140px 90px 80px 1fr; gap: 0.4em 0.8em; font: 0.85em -apple-system, Segoe UI, sans-serif; }
  .ss-timeline li .ts     { color: #666; }
  .ss-timeline li .kind   { color: #555; text-transform: uppercase; font-size: 0.78em; font-weight: 600; }
  .ss-timeline li .sev    { font-size: 0.78em; text-transform: uppercase; font-weight: 600; }
  .ss-timeline li .title  { font-weight: 600; color: #222; }
  .ss-timeline li .detail { grid-column: 4 / 5; color: #444; }
  .ss-timeline li.sev-critical { border-left-color: #b71c1c; }
  .ss-timeline li.sev-high     { border-left-color: #d84315; }
  .ss-timeline li.sev-medium   { border-left-color: #ef6c00; }
  .ss-timeline li.sev-low      { border-left-color: #689f38; }
  .ss-timeline li.sev-info     { border-left-color: #607d8b; }
  .ss-timeline li.sev-critical .sev { color: #b71c1c; }
  .ss-timeline li.sev-high     .sev { color: #d84315; }
  .ss-timeline li.sev-medium   .sev { color: #ef6c00; }
  .ss-timeline li.sev-low      .sev { color: #689f38; }
  .ss-timeline li.sev-info     .sev { color: #455a64; }
</style>"""
