"""skillscan CLI — phase S0.

Currently supports:
    skillscan inventory [PATH] [--format json|markdown] [--output FILE]

Scans the given path (default: cwd) plus user-global locations for AI
agent skills, MCP servers, and harness configs and prints an inventory.
Rule analysis arrives in S1.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from skillscan.discover import (
    discover_claude_harness,
    discover_claude_skills,
    discover_mcp_servers,
)
from skillscan.models import ScanResult
from skillscan.reporters import to_json, to_markdown


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skillscan", description="Security scanner for AI agent skills, MCP servers, and harness configs")
    sub = parser.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("inventory", help="Discover skills, MCP servers, and harness configs")
    inv.add_argument("path", nargs="?", default=".", help="Project root to scan (default: cwd)")
    inv.add_argument("--format", choices=("json", "markdown"), default="json")
    inv.add_argument("--output", help="Write to file instead of stdout")
    inv.add_argument("--no-user-global", action="store_true", help="Skip ~/.claude/, ~/.cursor/, etc.")

    return parser


def _do_inventory(args: argparse.Namespace) -> int:
    scan_root = Path(args.path).resolve()
    if not scan_root.exists():
        print(f"error: {scan_root} does not exist", file=sys.stderr)
        return 2

    result = ScanResult()
    result.artifacts.extend(discover_claude_skills(scan_root))
    result.artifacts.extend(discover_claude_harness(scan_root))
    result.artifacts.extend(discover_mcp_servers(scan_root))

    if args.format == "json":
        rendered = to_json(result)
    else:
        rendered = to_markdown(result)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "inventory":
        return _do_inventory(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
