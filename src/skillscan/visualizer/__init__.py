"""SVG visualizers — pure-Python (no graphviz dep) outputs.

  mcp_graph.py    skill -> MCP server -> tool relationship graph
  trend_chart.py  drift trend over the SQLite baseline history
"""

from skillscan.visualizer.mcp_graph import render_mcp_graph_svg
from skillscan.visualizer.trend_chart import render_trend_svg

__all__ = ["render_mcp_graph_svg", "render_trend_svg"]
