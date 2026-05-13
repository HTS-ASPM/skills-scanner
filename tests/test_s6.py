"""Tests for S6 — drift trend chart + MCP graph SVG + Slack/Teams alerts."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from skillscan.alerts.slack import build_slack_payload, send_slack
from skillscan.alerts.teams import build_teams_payload, send_teams
from skillscan.cli import main
from skillscan.discover import discover_claude_skills, discover_mcp_servers
from skillscan.models import (
    Artifact,
    ArtifactKind,
    Finding,
    Host,
    ScanResult,
)
from skillscan.store import open_db, save_baseline
from skillscan.visualizer.mcp_graph import render_mcp_graph_svg
from skillscan.visualizer.trend_chart import render_trend_svg


def _project_skill(root: Path, name: str, *, frontmatter: str = "") -> None:
    skill_dir = root / ".claude" / "skills" / name
    skill_dir.mkdir(parents=True)
    if not frontmatter:
        frontmatter = f"name: {name}\ndescription: a test skill\nallowed-tools: [\"Read\"]"
    (skill_dir / "SKILL.md").write_text(f"---\n{frontmatter}\n---\nbody\n", encoding="utf-8")


def _project_artifacts(root: Path):
    return [a for a in discover_claude_skills(root) if str(a.path).startswith(str(root))]


def _f(rule_id: str, severity: str, artifact: Artifact, summary: str = "x") -> Finding:
    return Finding(
        rule_id=rule_id, category="static", severity=severity, confidence="high",
        summary=summary, artifact=artifact, file=artifact.path, line=None,
        evidence=[], references=[], metadata={},
    )


# --------------------------------------------------------------------------- #
# MCP graph viz
# --------------------------------------------------------------------------- #

class McpGraphTests(unittest.TestCase):
    def test_renders_svg_root(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "alpha", frontmatter='name: alpha\ndescription: x\nallowed-tools: ["Read", "Bash"]')
            (root / ".mcp.json").write_text(
                json.dumps({"mcpServers": {"fs": {"command": "node"}}}), encoding="utf-8",
            )
            artifacts = [a for a in _project_artifacts(root)] + [
                a for a in discover_mcp_servers(root) if str(a.path).startswith(str(root))
            ]
            svg = render_mcp_graph_svg(artifacts)
            self.assertIn("<svg", svg)
            self.assertIn("Skills", svg)
            self.assertIn("MCP servers", svg)
            self.assertIn("Tools granted", svg)
            self.assertIn("alpha", svg)
            self.assertIn("fs", svg)
            self.assertIn("Read", svg)

    def test_empty_input_renders_placeholder(self) -> None:
        svg = render_mcp_graph_svg([])
        self.assertIn("No skills or MCP servers", svg)


# --------------------------------------------------------------------------- #
# Trend chart
# --------------------------------------------------------------------------- #

class TrendChartTests(unittest.TestCase):
    def test_empty_db_returns_placeholder(self) -> None:
        with TemporaryDirectory() as tmp:
            svg = render_trend_svg(Path(tmp) / "missing.db", scan_root="/x")
            self.assertIn("No baseline history", svg)

    def test_history_renders_path(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "x")
            db = root / "skillscan.db"
            conn = open_db(db)
            artifacts = _project_artifacts(root)
            save_baseline(conn, str(root), artifacts)
            save_baseline(conn, str(root), artifacts + artifacts)  # bump artifact_count
            conn.close()
            svg = render_trend_svg(db, scan_root=str(root))
            self.assertIn("<svg", svg)
            self.assertIn("artifacts", svg)


# --------------------------------------------------------------------------- #
# Slack alert
# --------------------------------------------------------------------------- #

class SlackAlertTests(unittest.TestCase):
    def _result(self, *findings: Finding) -> ScanResult:
        result = ScanResult()
        result.findings.extend(findings)
        return result

    def _artifact(self) -> Artifact:
        return Artifact(kind=ArtifactKind.SKILL, host=Host.CLAUDE_CODE, name="x", path=Path("/tmp/x"))

    def test_threshold_filter(self) -> None:
        a = self._artifact()
        result = self._result(_f("a", "low", a), _f("b", "high", a), _f("c", "critical", a))
        payload = build_slack_payload(result, threshold="high")
        self.assertIn("blocks", payload)
        text_blob = json.dumps(payload)
        self.assertNotIn("`a`", text_blob)   # filtered out
        self.assertIn("`b`", text_blob)
        self.assertIn("`c`", text_blob)

    def test_no_payload_when_below_threshold(self) -> None:
        a = self._artifact()
        result = self._result(_f("a", "low", a))
        payload = build_slack_payload(result, threshold="high")
        self.assertEqual(payload, {})

    def test_send_slack_uses_requester(self) -> None:
        captured: dict = {}
        def requester(url, body, headers):
            captured["url"] = url
            captured["body"] = body
            captured["headers"] = headers
        a = self._artifact()
        result = self._result(_f("a", "critical", a))
        send_slack("https://hooks.slack.example/T/B/X", result, threshold="critical", host_id="dev-1", requester=requester)
        self.assertEqual(captured["url"], "https://hooks.slack.example/T/B/X")
        self.assertEqual(captured["headers"]["Content-Type"], "application/json")
        body = json.loads(captured["body"])
        self.assertIn("blocks", body)


# --------------------------------------------------------------------------- #
# Teams alert
# --------------------------------------------------------------------------- #

class TeamsAlertTests(unittest.TestCase):
    def _artifact(self) -> Artifact:
        return Artifact(kind=ArtifactKind.SKILL, host=Host.CLAUDE_CODE, name="x", path=Path("/tmp/x"))

    def test_adaptive_card_shape(self) -> None:
        result = ScanResult()
        result.findings.append(_f("a", "critical", self._artifact()))
        payload = build_teams_payload(result, threshold="critical")
        self.assertEqual(payload["type"], "message")
        attach = payload["attachments"][0]
        self.assertEqual(attach["contentType"], "application/vnd.microsoft.card.adaptive")
        self.assertEqual(attach["content"]["version"], "1.4")

    def test_send_teams_uses_requester(self) -> None:
        captured: dict = {}
        def requester(url, body, headers):
            captured["url"] = url
            captured["body"] = body
        result = ScanResult()
        result.findings.append(_f("a", "high", self._artifact()))
        send_teams("https://outlook.office.com/webhook/X", result, threshold="high", requester=requester)
        self.assertEqual(captured["url"], "https://outlook.office.com/webhook/X")
        body = json.loads(captured["body"])
        self.assertIn("attachments", body)


# --------------------------------------------------------------------------- #
# CLI integration
# --------------------------------------------------------------------------- #

class CliS6Tests(unittest.TestCase):
    def test_dashboard_includes_mcp_graph(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "demo")
            (root / ".mcp.json").write_text(
                json.dumps({"mcpServers": {"fs": {"command": "node"}}}), encoding="utf-8",
            )
            out = root / "dash.html"
            rc = main(["dashboard", str(root), "--no-user-global", "--db", str(root / "no.db"), "--output", str(out)])
            self.assertEqual(rc, 0)
            html_doc = out.read_text()
            self.assertIn("Skill ↔ MCP ↔ tool graph", html_doc)
            self.assertIn("Drift trend", html_doc)

    def test_dashboard_without_baseline_still_renders(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "demo")
            out = root / "dash.html"
            rc = main(["dashboard", str(root), "--no-user-global", "--db", str(root / "missing.db"), "--output", str(out)])
            self.assertEqual(rc, 0)
            self.assertIn("No baseline history", out.read_text())


if __name__ == "__main__":
    unittest.main()
