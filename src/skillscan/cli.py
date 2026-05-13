"""skillscan CLI.

Commands:
    skillscan inventory [PATH]   Discover artifacts (no rule analysis)
    skillscan scan      [PATH]   Discover + run S1 rule engine
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from skillscan.collusion import analyze as analyze_collusion
from skillscan.discover import (
    discover_claude_harness,
    discover_claude_skills,
    discover_mcp_servers,
)
from skillscan.models import ScanResult
from skillscan.reporters import to_json, to_markdown, to_sarif
from skillscan.rules import run_rules
from skillscan.rules.drift import findings_for_drift
from skillscan.store import (
    default_db_path,
    diff_against_baseline,
    latest_baseline,
    open_db,
    save_baseline,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillscan",
        description="Security scanner for AI agent skills, MCP servers, and harness configs",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("inventory", "Discover skills, MCP servers, and harness configs (no rules)"),
        ("scan", "Discover + run rule engine (Tier-0 + capability + drift)"),
    ):
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("path", nargs="?", default=".", help="Project root to scan (default: cwd)")
        cmd.add_argument(
            "--format",
            choices=("json", "markdown", "sarif"),
            default="json",
            help="Output format",
        )
        cmd.add_argument("--output", help="Write to file instead of stdout")
        cmd.add_argument(
            "--no-user-global",
            action="store_true",
            help="Skip ~/.claude/, ~/.cursor/, etc.",
        )
        cmd.add_argument(
            "--fail-on",
            choices=("critical", "high", "medium", "low"),
            help="Exit non-zero if any finding meets/exceeds this severity",
        )
        if name == "scan":
            cmd.add_argument(
                "--baseline",
                action="store_true",
                help="Compare against the most recent saved baseline and emit drift findings",
            )
            cmd.add_argument(
                "--save-baseline",
                action="store_true",
                help="Save the current artifact set as a new baseline after scanning",
            )
            cmd.add_argument(
                "--db",
                help=f"SQLite baseline DB (default: {default_db_path()})",
            )
            cmd.add_argument(
                "--judge",
                action="store_true",
                help="Enable optional NL judge (requires ANTHROPIC_API_KEY + anthropic package)",
            )

    return parser


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _discover(scan_root: Path) -> ScanResult:
    result = ScanResult()
    result.artifacts.extend(discover_claude_skills(scan_root))
    result.artifacts.extend(discover_claude_harness(scan_root))
    result.artifacts.extend(discover_mcp_servers(scan_root))
    return result


def _render(result: ScanResult, fmt: str) -> str:
    if fmt == "json":
        return to_json(result)
    if fmt == "sarif":
        return to_sarif(result)
    return to_markdown(result)


def _emit(rendered: str, output: str | None) -> None:
    if output:
        Path(output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)


def _exit_code_for(result: ScanResult, fail_on: str | None) -> int:
    if not fail_on:
        return 0
    threshold = _SEVERITY_RANK[fail_on]
    for finding in result.findings:
        if _SEVERITY_RANK.get(finding.severity, 0) >= threshold:
            return 3
    return 0


def _do_inventory(args: argparse.Namespace) -> int:
    scan_root = Path(args.path).resolve()
    if not scan_root.exists():
        print(f"error: {scan_root} does not exist", file=sys.stderr)
        return 2
    result = _discover(scan_root)
    _emit(_render(result, args.format), args.output)
    return 0


def _do_scan(args: argparse.Namespace) -> int:
    scan_root = Path(args.path).resolve()
    if not scan_root.exists():
        print(f"error: {scan_root} does not exist", file=sys.stderr)
        return 2
    result = _discover(scan_root)
    result.findings.extend(run_rules(result.artifacts, with_judge=getattr(args, "judge", False)))
    result.findings.extend(analyze_collusion(result.artifacts, result.findings))

    if getattr(args, "baseline", False) or getattr(args, "save_baseline", False):
        db_path = Path(args.db) if args.db else default_db_path()
        conn = open_db(db_path)
        try:
            if args.baseline:
                baseline = latest_baseline(conn, str(scan_root))
                if baseline:
                    signals = diff_against_baseline(result.artifacts, baseline)
                    result.findings.extend(findings_for_drift(signals))
            if args.save_baseline:
                save_baseline(conn, str(scan_root), result.artifacts)
        finally:
            conn.close()

    _emit(_render(result, args.format), args.output)
    return _exit_code_for(result, args.fail_on)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "inventory":
        return _do_inventory(args)
    if args.command == "scan":
        return _do_scan(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
