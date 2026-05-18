"""Interactive skill ↔ MCP ↔ tool graph — pure HTML + inline JS.

Drop-in replacement for the static SVG in visualizer/mcp_graph.py.
The output is a single self-contained HTML fragment with:

  - inline <style> for visuals
  - inline <script> implementing a tiny force-directed layout
    (Verlet integration with spring + repulsion forces; no D3/Cytoscape
    dependency, no external CDN load)
  - data baked in via a JSON literal so the page works offline

Designed to be dropped into the existing dashboard's section block.
"""

from __future__ import annotations

import html
import json

from skillscan.models import Artifact, ArtifactKind


def render_interactive_graph_html(artifacts: list[Artifact], *, height: int = 520) -> str:
    nodes, edges = _build_graph(artifacts)
    if not nodes:
        return (
            "<div class='aibom-interactive-graph empty'>"
            "<p><em>No skills or MCP servers discovered.</em></p></div>"
        )
    payload = json.dumps({"nodes": nodes, "edges": edges}, separators=(",", ":"))
    return _TEMPLATE.replace("/*PAYLOAD*/", html.escape(payload, quote=False)).replace("/*HEIGHT*/", str(height))


# --------------------------------------------------------------------------- #

def _build_graph(artifacts: list[Artifact]) -> tuple[list[dict], list[dict]]:
    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[str] = set()

    skills = [a for a in artifacts if a.kind == ArtifactKind.SKILL]
    mcps = [a for a in artifacts if a.kind == ArtifactKind.MCP_SERVER]
    tools: set[str] = set()
    for s in skills:
        for t in _normalize_tools((s.metadata or {}).get("allowed_tools")):
            if t == "*":
                continue
            tools.add(t)

    for s in skills:
        nid = f"skill::{s.host.value}::{s.name}"
        if nid in seen:
            continue
        seen.add(nid)
        nodes.append({"id": nid, "label": s.name, "type": "skill"})
    for m in mcps:
        nid = f"mcp::{m.host.value}::{m.name}"
        if nid in seen:
            continue
        seen.add(nid)
        nodes.append({"id": nid, "label": m.name, "type": "mcp"})
    for t in sorted(tools):
        nid = f"tool::{t}"
        if nid in seen:
            continue
        seen.add(nid)
        nodes.append({"id": nid, "label": t, "type": "tool"})

    for s in skills:
        skill_id = f"skill::{s.host.value}::{s.name}"
        for t in _normalize_tools((s.metadata or {}).get("allowed_tools")):
            if t == "*" or t not in tools:
                continue
            edges.append({"source": skill_id, "target": f"tool::{t}", "kind": "uses"})
        for m in mcps:
            if m.host == s.host:
                edges.append({
                    "source": skill_id,
                    "target": f"mcp::{m.host.value}::{m.name}",
                    "kind": "can-invoke",
                })
    return nodes, edges


def _normalize_tools(value) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return []


_TEMPLATE = """
<div class="ss-igraph" style="height: /*HEIGHT*/px; position: relative;">
  <svg width="100%" height="/*HEIGHT*/" style="display:block;background:#fafafa;border:1px solid #ddd;border-radius:6px"></svg>
  <div class="ss-igraph-legend">
    <span class="ss-leg-dot skill"></span> Skill
    <span class="ss-leg-dot mcp"></span> MCP server
    <span class="ss-leg-dot tool"></span> Tool
    <span class="ss-leg-edge solid"></span> uses
    <span class="ss-leg-edge dashed"></span> can-invoke (blast radius)
  </div>
</div>
<style>
  .ss-igraph svg circle.skill { fill: #1565c0; }
  .ss-igraph svg circle.mcp   { fill: #6a1b9a; }
  .ss-igraph svg circle.tool  { fill: #2e7d32; }
  .ss-igraph svg line.uses        { stroke: #2e7d32; stroke-width: 1.4; opacity: 0.75; }
  .ss-igraph svg line.can-invoke  { stroke: #6a1b9a; stroke-width: 1; opacity: 0.5; stroke-dasharray: 4 4; }
  .ss-igraph svg text { font: 11px -apple-system, Segoe UI, sans-serif; fill: #1a1a1a; pointer-events: none; }
  .ss-igraph svg circle { cursor: grab; }
  .ss-igraph svg circle:active { cursor: grabbing; }
  .ss-igraph-legend { position: absolute; top: 8px; right: 8px; background: #ffffffd9; padding: 6px 10px;
                      border-radius: 4px; font: 11px -apple-system, Segoe UI, sans-serif; color: #444; }
  .ss-igraph-legend .ss-leg-dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin: 0 4px 0 8px; vertical-align: middle; }
  .ss-igraph-legend .ss-leg-dot.skill { background: #1565c0; }
  .ss-igraph-legend .ss-leg-dot.mcp   { background: #6a1b9a; }
  .ss-igraph-legend .ss-leg-dot.tool  { background: #2e7d32; }
  .ss-igraph-legend .ss-leg-edge { display:inline-block; width:24px; height:0; border-top: 1.4px solid #2e7d32;
                                   margin: 0 4px 0 8px; vertical-align: middle; }
  .ss-igraph-legend .ss-leg-edge.dashed { border-top: 1px dashed #6a1b9a; }
</style>
<script>
(function() {
  var data = JSON.parse('/*PAYLOAD*/'.replace(/&quot;/g,'"').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>'));
  var container = document.currentScript.previousElementSibling;
  while (container && !container.classList.contains('ss-igraph')) {
    container = container.previousElementSibling;
  }
  if (!container) return;
  var svg = container.querySelector('svg');
  var W = svg.clientWidth || 800;
  var H = parseInt(svg.getAttribute('height'), 10) || 500;

  // Seed positions deterministically (radial by type column).
  var nodesById = {};
  var typeOrder = { skill: 0.18, mcp: 0.5, tool: 0.82 };
  var perType = { skill: 0, mcp: 0, tool: 0 };
  data.nodes.forEach(function(n){
    n.x = W * (typeOrder[n.type] || 0.5);
    n.y = 40 + (perType[n.type] || 0) * 32;
    n.vx = 0; n.vy = 0;
    perType[n.type] = (perType[n.type] || 0) + 1;
    nodesById[n.id] = n;
  });

  // Force-directed Verlet step.
  function step() {
    var k = 0.06, repulsion = 1400, spring = 0.012, springLen = 90;
    data.nodes.forEach(function(a){
      data.nodes.forEach(function(b){
        if (a === b) return;
        var dx = a.x - b.x, dy = a.y - b.y;
        var d2 = dx*dx + dy*dy + 0.1;
        var f = repulsion / d2;
        a.vx += (dx / Math.sqrt(d2)) * f * k;
        a.vy += (dy / Math.sqrt(d2)) * f * k;
      });
    });
    data.edges.forEach(function(e){
      var a = nodesById[e.source], b = nodesById[e.target];
      if (!a || !b) return;
      var dx = b.x - a.x, dy = b.y - a.y;
      var dist = Math.sqrt(dx*dx + dy*dy) || 1;
      var f = (dist - springLen) * spring;
      a.vx += (dx / dist) * f; a.vy += (dy / dist) * f;
      b.vx -= (dx / dist) * f; b.vy -= (dy / dist) * f;
    });
    data.nodes.forEach(function(n){
      n.vx *= 0.85; n.vy *= 0.85;
      n.x += n.vx; n.y += n.vy;
      // Soft walls.
      n.x = Math.max(20, Math.min(W - 20, n.x));
      n.y = Math.max(20, Math.min(H - 20, n.y));
    });
  }

  function render() {
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    // Edges first.
    data.edges.forEach(function(e){
      var a = nodesById[e.source], b = nodesById[e.target];
      if (!a || !b) return;
      var line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
      line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
      line.setAttribute('class', e.kind);
      svg.appendChild(line);
    });
    // Nodes.
    data.nodes.forEach(function(n){
      var c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      c.setAttribute('cx', n.x); c.setAttribute('cy', n.y);
      c.setAttribute('r', 7); c.setAttribute('class', n.type);
      c.setAttribute('data-id', n.id);
      svg.appendChild(c);
      var t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      t.setAttribute('x', n.x + 10); t.setAttribute('y', n.y + 4);
      t.textContent = n.label;
      svg.appendChild(t);
    });
  }

  // Run ~120 iterations for layout, then render every 50ms while user drags.
  for (var i = 0; i < 120; i++) step();
  render();

  // Drag interaction.
  var dragging = null;
  svg.addEventListener('mousedown', function(e){
    if (e.target.tagName !== 'circle') return;
    dragging = nodesById[e.target.getAttribute('data-id')];
  });
  svg.addEventListener('mousemove', function(e){
    if (!dragging) return;
    var rect = svg.getBoundingClientRect();
    dragging.x = e.clientX - rect.left;
    dragging.y = e.clientY - rect.top;
    dragging.vx = 0; dragging.vy = 0;
    for (var i = 0; i < 6; i++) step();
    render();
  });
  function up(){ dragging = null; }
  svg.addEventListener('mouseup', up);
  svg.addEventListener('mouseleave', up);
})();
</script>
"""
