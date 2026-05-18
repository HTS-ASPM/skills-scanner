"""Executive HTML dashboard for skills-scanner.

Single self-contained page summarising a scan: KPIs, severity
distribution, top hosts, top rule_ids, drift / collusion summary.
No external CSS/JS — drops into any HTTP server or local file viewer.
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from skillscan.models import ScanResult
from skillscan.visualizer import (
    build_timeline,
    render_interactive_graph_html,
    render_mcp_graph_svg,
    render_timeline_html,
    render_trend_svg,
)


def generate_dashboard_html(
    result: ScanResult,
    *,
    baseline_db: Path | None = None,
    scan_root: str | None = None,
    interactive_graph: bool = True,
) -> str:
    parts: list[str] = [_HEAD]
    parts.append("<header>")
    parts.append("<h1>Skills Scanner — Executive Dashboard</h1>")
    parts.append(f"<p class='meta'>Generated {_now()}</p>")
    parts.append("</header>")

    parts.append("<section class='kpis'>")
    parts.append(_kpi("Artifacts", len(result.artifacts)))
    parts.append(_kpi("Findings", len(result.findings)))
    crit = sum(1 for f in result.findings if f.severity == "critical")
    parts.append(_kpi("Critical", crit))
    drift = sum(1 for f in result.findings if f.category == "drift")
    parts.append(_kpi("Drift signals", drift))
    collusion = sum(1 for f in result.findings if f.category == "collusion")
    parts.append(_kpi("Collusion signals", collusion))
    parts.append("</section>")

    parts.append(_severity_block(result))
    parts.append(_top_rules_block(result))
    parts.append(_artifact_breakdown_block(result))
    if baseline_db and scan_root:
        parts.append(_drift_trend_block(baseline_db, scan_root))
    parts.append(_mcp_graph_block(result, interactive=interactive_graph))
    parts.append(_timeline_block(result, baseline_db=baseline_db, scan_root=scan_root))
    parts.append(_critical_findings_block(result))

    parts.append(_FOOT)
    return "".join(parts)


def _drift_trend_block(db_path: Path, scan_root: str) -> str:
    svg = render_trend_svg(db_path, scan_root)
    return "<section><h2>Drift trend</h2>" + svg + "</section>"


def _mcp_graph_block(result: ScanResult, *, interactive: bool = True) -> str:
    if interactive:
        body = render_interactive_graph_html(result.artifacts)
    else:
        body = render_mcp_graph_svg(result.artifacts)
    return "<section><h2>Skill ↔ MCP ↔ tool graph</h2>" + body + "</section>"


def _timeline_block(result: ScanResult, *, baseline_db: Path | None = None, scan_root: str | None = None) -> str:
    events = build_timeline(result, baseline_db=baseline_db, scan_root=scan_root)
    return "<section><h2>Incident timeline</h2>" + render_timeline_html(events) + "</section>"


# --------------------------------------------------------------------------- #

def _kpi(label: str, value) -> str:
    return f"<div class='kpi'><div class='kpi-value'>{html.escape(str(value))}</div><div class='kpi-label'>{html.escape(label)}</div></div>"


def _severity_block(result: ScanResult) -> str:
    counts = Counter(f.severity for f in result.findings)
    total = sum(counts.values()) or 1
    bars = []
    for sev in ("critical", "high", "medium", "low", "info"):
        count = counts.get(sev, 0)
        pct = (count / total) * 100
        bars.append(
            f"<div class='bar-row'>"
            f"<span class='bar-label sev-{sev}'>{sev}</span>"
            f"<div class='bar'><div class='bar-fill sev-{sev}-bg' style='width:{pct:.1f}%'></div></div>"
            f"<span class='bar-count'>{count}</span>"
            f"</div>"
        )
    return "<section><h2>Findings by severity</h2>" + "".join(bars) + "</section>"


def _top_rules_block(result: ScanResult) -> str:
    counts = Counter(f.rule_id for f in result.findings).most_common(10)
    if not counts:
        return ""
    rows = ["<section><h2>Top rules</h2><table><thead><tr><th>Rule</th><th>Count</th></tr></thead><tbody>"]
    for rule, count in counts:
        rows.append(f"<tr><td><code>{html.escape(rule)}</code></td><td>{count}</td></tr>")
    rows.append("</tbody></table></section>")
    return "".join(rows)


def _artifact_breakdown_block(result: ScanResult) -> str:
    by_kind = Counter(a.kind.value for a in result.artifacts)
    by_host = Counter(a.host.value for a in result.artifacts)
    if not by_kind and not by_host:
        return ""
    rows = ["<section><h2>Artifacts</h2>",
            "<div class='cols'><div><h3>By kind</h3><table><tbody>"]
    for k, v in sorted(by_kind.items()):
        rows.append(f"<tr><td><code>{html.escape(k)}</code></td><td>{v}</td></tr>")
    rows.append("</tbody></table></div><div><h3>By host</h3><table><tbody>")
    for k, v in sorted(by_host.items()):
        rows.append(f"<tr><td><code>{html.escape(k)}</code></td><td>{v}</td></tr>")
    rows.append("</tbody></table></div></div></section>")
    return "".join(rows)


def _critical_findings_block(result: ScanResult) -> str:
    crit_or_high = [f for f in result.findings if f.severity in {"critical", "high"}]
    if not crit_or_high:
        return ""
    rows = ["<section><h2>Critical &amp; high findings</h2>"
            "<table><thead><tr><th>Severity</th><th>Rule</th><th>Artifact</th><th>Summary</th></tr></thead><tbody>"]
    for f in crit_or_high[:50]:
        rows.append(
            "<tr>"
            f"<td class='sev sev-{html.escape(f.severity)}'>{html.escape(f.severity)}</td>"
            f"<td><code>{html.escape(f.rule_id)}</code></td>"
            f"<td>{html.escape(f.artifact.name)}</td>"
            f"<td>{html.escape(f.summary[:160])}</td>"
            "</tr>"
        )
    rows.append("</tbody></table></section>")
    return "".join(rows)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


_HEAD = """<!DOCTYPE html>
<html lang='en'><head><meta charset='utf-8'>
<title>Skills Scanner — Executive Dashboard</title>
<style>
  body { font-family: -apple-system, system-ui, Segoe UI, sans-serif; margin: 2em auto; max-width: 1100px; color: #1a1a1a; }
  header { border-bottom: 2px solid #333; padding-bottom: 1em; margin-bottom: 2em; }
  h1 { margin: 0; font-size: 1.6em; }
  .meta { color: #555; font-size: 0.9em; margin: 0.3em 0; }
  section { margin-bottom: 2em; }
  h2 { font-size: 1.15em; border-bottom: 1px solid #ccc; padding-bottom: 0.3em; }
  h3 { font-size: 0.95em; margin: 0 0 0.4em 0; }
  .kpis { display: flex; gap: 1em; flex-wrap: wrap; }
  .kpi { flex: 1; min-width: 140px; padding: 1em; border: 1px solid #ddd; border-radius: 6px; background: #fafafa; text-align: center; }
  .kpi-value { font-size: 1.8em; font-weight: 700; }
  .kpi-label { font-size: 0.85em; color: #666; margin-top: 0.3em; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
  th, td { text-align: left; padding: 0.4em 0.6em; border-bottom: 1px solid #eee; }
  th { background: #f6f6f6; }
  code { font-size: 0.85em; background: #f0f0f0; padding: 1px 4px; border-radius: 3px; }
  .bar-row { display: flex; align-items: center; gap: 0.6em; margin: 0.3em 0; }
  .bar-label { display: inline-block; width: 80px; font-size: 0.85em; text-transform: uppercase; font-weight: 600; }
  .bar { flex: 1; height: 14px; background: #f0f0f0; border-radius: 4px; overflow: hidden; }
  .bar-fill { height: 100%; }
  .bar-count { width: 50px; text-align: right; font-variant-numeric: tabular-nums; color: #555; }
  .cols { display: flex; gap: 2em; }
  .cols > div { flex: 1; }
  .sev { font-weight: 600; text-transform: uppercase; font-size: 0.78em; }
  .sev-critical-bg { background: #b71c1c; } .sev-critical { color: #b71c1c; }
  .sev-high-bg { background: #d84315; } .sev-high { color: #d84315; }
  .sev-medium-bg { background: #ef6c00; } .sev-medium { color: #ef6c00; }
  .sev-low-bg { background: #689f38; } .sev-low { color: #689f38; }
  .sev-info-bg { background: #607d8b; } .sev-info { color: #455a64; }
</style></head><body>
"""

_FOOT = "</body></html>"
