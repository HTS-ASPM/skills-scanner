"""Discover Claude skills, agents, commands, and harness configs.

Search locations (in priority order):
  ~/.claude/skills/         — user-global skills
  <root>/.claude/skills/    — project-local skills
  ~/.claude/agents/         — user-global agent definitions
  <root>/.claude/agents/
  ~/.claude/commands/       — slash commands
  <root>/.claude/commands/
  ~/.claude/CLAUDE.md       — user-global instructions
  <root>/CLAUDE.md
  ~/.claude/settings.json   — user-global settings
  <root>/.claude/settings.json
"""

from __future__ import annotations

from pathlib import Path

from skillscan.models import Artifact, ArtifactKind, Host
from skillscan.parse.skill_md import parse_skill_md


def _candidate_skill_roots(scan_root: Path) -> list[Path]:
    home = Path.home()
    return [
        home / ".claude" / "skills",
        scan_root / ".claude" / "skills",
    ]


def _candidate_agent_roots(scan_root: Path) -> list[Path]:
    home = Path.home()
    return [
        home / ".claude" / "agents",
        scan_root / ".claude" / "agents",
    ]


def _candidate_command_roots(scan_root: Path) -> list[Path]:
    home = Path.home()
    return [
        home / ".claude" / "commands",
        scan_root / ".claude" / "commands",
    ]


def _candidate_harness_files(scan_root: Path) -> list[Path]:
    home = Path.home()
    return [
        home / ".claude" / "CLAUDE.md",
        scan_root / "CLAUDE.md",
        home / ".claude" / "settings.json",
        scan_root / ".claude" / "settings.json",
        scan_root / ".claude" / "settings.local.json",
        home / ".claude" / "keybindings.json",
    ]


def discover_claude_skills(scan_root: Path) -> list[Artifact]:
    """Find every SKILL.md under known skill roots; bundle siblings as artifacts."""
    artifacts: list[Artifact] = []
    for root in _candidate_skill_roots(scan_root):
        if not root.exists() or not root.is_dir():
            continue
        for skill_md in root.rglob("SKILL.md"):
            bundle_dir = skill_md.parent
            bundled = [p for p in bundle_dir.rglob("*") if p.is_file() and p != skill_md]
            parsed = parse_skill_md(skill_md)
            artifacts.append(
                Artifact(
                    kind=ArtifactKind.SKILL,
                    host=Host.CLAUDE_CODE,
                    name=parsed.get("name") or bundle_dir.name,
                    path=skill_md,
                    bundled_files=bundled,
                    raw=parsed,
                    metadata={
                        "description": parsed.get("description"),
                        "allowed_tools": parsed.get("allowed-tools"),
                        "disable_model_invocation": parsed.get("disable-model-invocation"),
                        "scope": "user" if str(root).startswith(str(Path.home())) else "project",
                        "bundle_size": len(bundled) + 1,
                    },
                )
            )
    return artifacts


def discover_claude_harness(scan_root: Path) -> list[Artifact]:
    """Pick up CLAUDE.md, settings.json, agents/, commands/ as harness artifacts."""
    artifacts: list[Artifact] = []
    for path in _candidate_harness_files(scan_root):
        if path.exists() and path.is_file():
            artifacts.append(
                Artifact(
                    kind=ArtifactKind.HARNESS_CONFIG,
                    host=Host.CLAUDE_CODE,
                    name=path.name,
                    path=path,
                    metadata={"scope": "user" if str(path).startswith(str(Path.home())) else "project"},
                )
            )
    for root in _candidate_agent_roots(scan_root):
        if not root.exists():
            continue
        for f in root.rglob("*.md"):
            artifacts.append(
                Artifact(
                    kind=ArtifactKind.AGENT_DEFINITION,
                    host=Host.CLAUDE_CODE,
                    name=f.stem,
                    path=f,
                    metadata={"scope": "user" if str(root).startswith(str(Path.home())) else "project"},
                )
            )
    for root in _candidate_command_roots(scan_root):
        if not root.exists():
            continue
        for f in root.rglob("*.md"):
            artifacts.append(
                Artifact(
                    kind=ArtifactKind.SLASH_COMMAND,
                    host=Host.CLAUDE_CODE,
                    name=f.stem,
                    path=f,
                    metadata={"scope": "user" if str(root).startswith(str(Path.home())) else "project"},
                )
            )
    return artifacts
