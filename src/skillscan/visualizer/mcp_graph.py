"""Pure-Python SVG graph viz for skill <-> MCP server relationships.

No graphviz / pygraphviz dep. Layout is a deterministic three-column
arrangement (skills | mcp servers | declared tools) with edges drawn
between connected nodes. The output is a single self-contained <svg>
element that drops into the dashboard or any HTML page.

Edge derivation:
  skill --uses--> tool       from SKILL.md frontmatter `allowed-tools`
  skill --can-invoke--> mcp  one edge per discovered MCP server
                             (every skill running under the same agent
                             host can in principle invoke any MCP server
                             on that host — that *is* the blast radius
                             we want to visualize)
"""

from __future__ import annotations

from dataclasses import dataclass

from skillscan.models import Artifact, ArtifactKind


@dataclass(frozen=True)
class _Node:
    id: str
    label: str
    column: int  # 0 = skill, 1 = mcp, 2 = tool
    x: float = 0
    y: float = 0


@dataclass(frozen=True)
class _Edge:
    source_id: str
    target_id: str
    kind: str  # "uses" | "can-invoke"


_COLUMN_X = {0: 80, 1: 360, 2: 640}
_COLUMN_TITLE = {0: "Skills", 1: "MCP servers", 2: "Tools granted"}
_NODE_RADIUS = 6
_NODE_VSPACING = 28


def render_mcp_graph_svg(artifacts: list[Artifact], *, width: int = 760, padding: int = 60) -> str:
    nodes, edges = _build_graph(artifacts)
    if not nodes:
        return _empty_svg(width)

    # Lay out: each column gets equal vertical spacing.
    by_col: dict[int, list[_Node]] = {0: [], 1: [], 2: []}
    for n in nodes:
        by_col[n.column].append(n)
    laid: list[_Node] = []
    max_col_count = max((len(v) for v in by_col.values()), default=1)
    height = padding * 2 + max_col_count * _NODE_VSPACING
    for col, items in by_col.items():
        x = _COLUMN_X[col]
        for i, n in enumerate(sorted(items, key=lambda nn: nn.label.lower())):
            y = padding + i * _NODE_VSPACING + _NODE_VSPACING // 2
            laid.append(_Node(id=n.id, label=n.label, column=n.column, x=x, y=y))
    pos = {n.id: (n.x, n.y) for n in laid}

    parts: list[str] = []
    parts.append(
        f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {width} {height}' "
        f"width='100%' height='{height}' role='img' "
        "aria-label='Skill to MCP to tool graph'>"
    )
    parts.append(_STYLE)

    # Column headers
    for col, title in _COLUMN_TITLE.items():
        parts.append(
            f"<text x='{_COLUMN_X[col]}' y='28' class='col-title'>{_escape(title)}</text>"
        )

    # Edges first so nodes render on top
    for e in edges:
        if e.source_id not in pos or e.target_id not in pos:
            continue
        x1, y1 = pos[e.source_id]
        x2, y2 = pos[e.target_id]
        css = "edge-uses" if e.kind == "uses" else "edge-invoke"
        parts.append(
            f"<path d='M{x1+_NODE_RADIUS},{y1} C{(x1+x2)/2},{y1} {(x1+x2)/2},{y2} {x2-_NODE_RADIUS},{y2}' "
            f"class='{css}' fill='none'/>"
        )

    # Nodes + labels
    for n in laid:
        css = ("node-skill", "node-mcp", "node-tool")[n.column]
        parts.append(f"<circle cx='{n.x}' cy='{n.y}' r='{_NODE_RADIUS}' class='{css}'/>")
        anchor = "start" if n.column < 2 else "end"
        text_x = n.x + (_NODE_RADIUS + 4) if n.column < 2 else n.x - (_NODE_RADIUS + 4)
        parts.append(
            f"<text x='{text_x}' y='{n.y + 4}' class='node-label' text-anchor='{anchor}'>{_escape(n.label)}</text>"
        )

    parts.append("</svg>")
    return "".join(parts)


# --------------------------------------------------------------------------- #

def _build_graph(artifacts: list[Artifact]) -> tuple[list[_Node], list[_Edge]]:
    nodes: dict[str, _Node] = {}
    edges: list[_Edge] = []

    skills = [a for a in artifacts if a.kind == ArtifactKind.SKILL]
    mcps = [a for a in artifacts if a.kind == ArtifactKind.MCP_SERVER]

    # Tool union across all skills (column 2)
    tools: set[str] = set()
    for s in skills:
        for t in _normalize_tools((s.metadata or {}).get("allowed_tools")):
            if t == "*":
                continue
            tools.add(t)

    for s in skills:
        nid = f"skill::{s.host.value}::{s.name}"
        nodes[nid] = _Node(id=nid, label=s.name, column=0)
    for m in mcps:
        nid = f"mcp::{m.host.value}::{m.name}"
        nodes[nid] = _Node(id=nid, label=m.name, column=1)
    for t in tools:
        nid = f"tool::{t}"
        nodes[nid] = _Node(id=nid, label=t, column=2)

    for s in skills:
        skill_id = f"skill::{s.host.value}::{s.name}"
        # skill -> tool edges
        for t in _normalize_tools((s.metadata or {}).get("allowed_tools")):
            if t == "*" or t not in tools:
                continue
            edges.append(_Edge(source_id=skill_id, target_id=f"tool::{t}", kind="uses"))
        # skill -> mcp edges (same host)
        for m in mcps:
            if m.host == s.host:
                edges.append(_Edge(source_id=skill_id, target_id=f"mcp::{m.host.value}::{m.name}", kind="can-invoke"))

    return list(nodes.values()), edges


def _normalize_tools(value) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return []


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
    )


def _empty_svg(width: int) -> str:
    return (
        f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {width} 80' width='100%' height='80'>"
        f"{_STYLE}<text x='{width // 2}' y='44' class='empty' text-anchor='middle'>No skills or MCP servers discovered.</text>"
        "</svg>"
    )


_STYLE = """<style>
  .col-title { font: 600 12px -apple-system, Segoe UI, sans-serif; fill: #555; text-anchor: middle; text-transform: uppercase; }
  .node-skill { fill: #1565c0; }
  .node-mcp   { fill: #6a1b9a; }
  .node-tool  { fill: #2e7d32; }
  .node-label { font: 11px -apple-system, Segoe UI, sans-serif; fill: #1a1a1a; }
  .edge-uses    { stroke: #2e7d32; stroke-width: 1.2; opacity: 0.7; }
  .edge-invoke  { stroke: #6a1b9a; stroke-width: 0.9; opacity: 0.4; stroke-dasharray: 3 3; }
  .empty { font: 13px -apple-system, Segoe UI, sans-serif; fill: #777; font-style: italic; }
</style>"""
