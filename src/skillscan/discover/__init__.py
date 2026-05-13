"""Discovery layer: find skills, MCP servers, and harness configs across hosts.

Each discoverer returns a list of Artifact objects with no analysis applied.
Analysis happens in skillscan.rules.
"""

from skillscan.discover.claude import discover_claude_skills, discover_claude_harness
from skillscan.discover.mcp import discover_mcp_servers

__all__ = [
    "discover_claude_skills",
    "discover_claude_harness",
    "discover_mcp_servers",
]
