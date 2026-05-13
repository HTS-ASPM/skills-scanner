"""Discover MCP server configs across known agent hosts.

Locations checked (per-host, mac/linux paths shown; Windows handled with %APPDATA%):
  Claude Desktop:  ~/Library/Application Support/Claude/claude_desktop_config.json   (macOS)
                   %APPDATA%/Claude/claude_desktop_config.json                        (Windows)
                   ~/.config/Claude/claude_desktop_config.json                        (Linux)
  Claude Code:     ~/.claude/settings.json (mcpServers key), <root>/.mcp.json
  Cursor:          ~/.cursor/mcp.json, <root>/.cursor/mcp.json
  Windsurf:        ~/.codeium/windsurf/mcp_config.json
  Cline (VS Code): ~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json
  Generic:         <root>/.mcp.json, <root>/mcp.json
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from skillscan.models import Artifact, ArtifactKind, Host


def _appdata() -> Path | None:
    val = os.environ.get("APPDATA")
    return Path(val) if val else None


def _claude_desktop_path() -> Path | None:
    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if sys.platform.startswith("linux"):
        return home / ".config" / "Claude" / "claude_desktop_config.json"
    if sys.platform == "win32":
        appdata = _appdata()
        return (appdata / "Claude" / "claude_desktop_config.json") if appdata else None
    return None


def _cline_path() -> Path | None:
    home = Path.home()
    if sys.platform == "darwin":
        return (
            home
            / "Library"
            / "Application Support"
            / "Code"
            / "User"
            / "globalStorage"
            / "saoudrizwan.claude-dev"
            / "settings"
            / "cline_mcp_settings.json"
        )
    return None


def _candidate_mcp_files(scan_root: Path) -> list[tuple[Path, Host]]:
    home = Path.home()
    candidates: list[tuple[Path, Host]] = []
    cd = _claude_desktop_path()
    if cd:
        candidates.append((cd, Host.CLAUDE_DESKTOP))
    candidates.extend([
        (home / ".claude" / "settings.json", Host.CLAUDE_CODE),
        (scan_root / ".claude" / "settings.json", Host.CLAUDE_CODE),
        (scan_root / ".mcp.json", Host.CLAUDE_CODE),
        (scan_root / "mcp.json", Host.UNKNOWN),
        (home / ".cursor" / "mcp.json", Host.CURSOR),
        (scan_root / ".cursor" / "mcp.json", Host.CURSOR),
        (home / ".codeium" / "windsurf" / "mcp_config.json", Host.WINDSURF),
    ])
    cline = _cline_path()
    if cline:
        candidates.append((cline, Host.CLINE))
    return candidates


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _extract_servers(config: dict[str, Any]) -> dict[str, Any]:
    """MCP server map lives under different keys depending on host."""
    for key in ("mcpServers", "mcp_servers", "servers"):
        val = config.get(key)
        if isinstance(val, dict):
            return val
    return {}


def discover_mcp_servers(scan_root: Path) -> list[Artifact]:
    artifacts: list[Artifact] = []
    seen: set[tuple[str, str]] = set()
    for path, host in _candidate_mcp_files(scan_root):
        if not path.exists() or not path.is_file():
            continue
        config = _load_json(path)
        if not config:
            continue
        servers = _extract_servers(config)
        for name, spec in servers.items():
            key = (str(path), name)
            if key in seen:
                continue
            seen.add(key)
            spec_dict = spec if isinstance(spec, dict) else {}
            artifacts.append(
                Artifact(
                    kind=ArtifactKind.MCP_SERVER,
                    host=host,
                    name=name,
                    path=path,
                    raw=spec_dict,
                    metadata={
                        "command": spec_dict.get("command"),
                        "args": spec_dict.get("args"),
                        "env_keys": list((spec_dict.get("env") or {}).keys()),
                        "url": spec_dict.get("url"),
                        "transport": _infer_transport(spec_dict),
                    },
                )
            )
    return artifacts


def _infer_transport(spec: dict[str, Any]) -> str:
    if spec.get("url"):
        return "http"
    if spec.get("command"):
        return "stdio"
    return "unknown"
