"""Smoke tests for phase S0 — discovery + parsers."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from skillscan.cli import main
from skillscan.discover import (
    discover_claude_harness,
    discover_claude_skills,
    discover_mcp_servers,
)
from skillscan.parse.skill_md import parse_skill_md


class SkillMdParserTests(unittest.TestCase):
    def test_parses_frontmatter(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "SKILL.md"
            path.write_text(
                """---
name: demo
description: a demo skill
allowed-tools: ["Read", "Bash"]
disable-model-invocation: false
---
Body here.
""",
                encoding="utf-8",
            )
            parsed = parse_skill_md(path)
            self.assertEqual(parsed["name"], "demo")
            self.assertEqual(parsed["description"], "a demo skill")
            self.assertEqual(parsed["allowed-tools"], ["Read", "Bash"])
            self.assertIs(parsed["disable-model-invocation"], False)
            self.assertIn("Body here.", parsed["body"])

    def test_no_frontmatter(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "SKILL.md"
            path.write_text("just a body", encoding="utf-8")
            parsed = parse_skill_md(path)
            self.assertEqual(parsed.get("body"), "just a body")


class DiscoveryTests(unittest.TestCase):
    def test_discovers_project_local_skill(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            skill_dir = root / ".claude" / "skills" / "hello"
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                """---
name: hello
description: greet the user
---
Say hi.
""",
                encoding="utf-8",
            )
            (skill_dir / "helper.py").write_text("print('hi')\n", encoding="utf-8")

            artifacts = discover_claude_skills(root)
            names = [a.name for a in artifacts if str(a.path).startswith(str(root))]
            self.assertIn("hello", names)

            project_artifact = next(a for a in artifacts if str(a.path).startswith(str(root)))
            self.assertEqual(project_artifact.metadata["scope"], "project")
            self.assertEqual(len(project_artifact.bundled_files), 1)

    def test_discovers_project_local_mcp(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".mcp.json").write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]},
                            "remote": {"url": "https://example.com/sse"},
                        }
                    }
                ),
                encoding="utf-8",
            )
            artifacts = discover_mcp_servers(root)
            local = [a for a in artifacts if str(a.path).startswith(str(root))]
            names = sorted(a.name for a in local)
            self.assertEqual(names, ["fs", "remote"])
            transports = {a.name: a.metadata["transport"] for a in local}
            self.assertEqual(transports, {"fs": "stdio", "remote": "http"})

    def test_discovers_project_claude_md(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "CLAUDE.md").write_text("# project rules\n", encoding="utf-8")
            artifacts = discover_claude_harness(root)
            local = [a for a in artifacts if str(a.path).startswith(str(root))]
            self.assertTrue(any(a.name == "CLAUDE.md" for a in local))


class CliTests(unittest.TestCase):
    def test_inventory_runs(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            rc = main(["inventory", tmp, "--no-user-global", "--output", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertIn("artifacts", data)
            self.assertIn("findings", data)
            self.assertIn("summary", data)


if __name__ == "__main__":
    unittest.main()
