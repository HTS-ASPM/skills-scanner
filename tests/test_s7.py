"""Tests for S7 — interactive HTML graph + timeline + PagerDuty/Opsgenie alerts."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from skillscan.alerts.opsgenie import build_opsgenie_payload, send_opsgenie
from skillscan.alerts.pagerduty import build_pagerduty_payload, send_pagerduty
from skillscan.cli import main
from skillscan.discover import discover_claude_skills, discover_mcp_servers
from skillscan.models import Artifact, ArtifactKind, Finding, Host, ScanResult
from skillscan.store import open_db, save_baseline
from skillscan.visualizer.interactive_graph import render_interactive_graph_html
from skillscan.visualizer.timeline import build_timeline, render_timeline_html


def _project_skill(root: Path, name: str, *, frontmatter: str = "") -> None:
    skill_dir = root / ".claude" / "skills" / name
    skill_dir.mkdir(parents=True)
    if not frontmatter:
        frontmatter = f"name: {name}\ndescription: t\nallowed-tools: [\"Read\"]"
    (skill_dir / "SKILL.md").write_text(f"---\n{frontmatter}\n---\nbody\n", encoding="utf-8")


def _project_artifacts(root: Path):
    return [a for a in discover_claude_skills(root) if str(a.path).startswith(str(root))]


def _f(rule: str, sev: str, artifact: Artifact, category: str = "static") -> Finding:
    return Finding(
        rule_id=rule, category=category, severity=sev, confidence="high",
        summary="x", artifact=artifact, file=artifact.path, line=None,
        evidence=[], references=[], metadata={},
    )


def _artifact() -> Artifact:
    return Artifact(kind=ArtifactKind.SKILL, host=Host.CLAUDE_CODE, name="x", path=Path("/tmp/x"))


# --------------------------------------------------------------------------- #
# Interactive graph
# --------------------------------------------------------------------------- #

class InteractiveGraphTests(unittest.TestCase):
    def test_empty_returns_placeholder(self) -> None:
        html = render_interactive_graph_html([])
        self.assertIn("No skills or MCP servers", html)

    def test_renders_svg_and_inline_script(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "alpha", frontmatter='name: alpha\ndescription: x\nallowed-tools: ["Read", "Bash"]')
            (root / ".mcp.json").write_text(
                json.dumps({"mcpServers": {"fs": {"command": "node"}}}), encoding="utf-8",
            )
            artifacts = _project_artifacts(root) + [
                a for a in discover_mcp_servers(root) if str(a.path).startswith(str(root))
            ]
            html = render_interactive_graph_html(artifacts)
            self.assertIn("<svg", html)
            self.assertIn("<script>", html)
            self.assertIn('"label":"alpha"', html)
            self.assertIn('"label":"fs"', html)
            self.assertIn('"type":"skill"', html)
            self.assertIn('"type":"mcp"', html)
            # Legend present
            self.assertIn("Skill", html)
            self.assertIn("can-invoke", html)

    def test_does_not_load_external_resources(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "x")
            html = render_interactive_graph_html(_project_artifacts(root))
            self.assertNotIn("<link ", html)
            self.assertNotIn("https://cdn", html)
            self.assertNotIn("<iframe", html)


# --------------------------------------------------------------------------- #
# Timeline
# --------------------------------------------------------------------------- #

class TimelineTests(unittest.TestCase):
    def test_empty_renders_placeholder(self) -> None:
        events = build_timeline(ScanResult())
        self.assertEqual(events, [])
        html = render_timeline_html(events)
        self.assertIn("No incidents recorded", html)

    def test_drift_and_critical_findings_added(self) -> None:
        a = _artifact()
        result = ScanResult()
        result.findings.extend([
            _f("drift.rug_pull", "critical", a, category="drift"),
            _f("collusion.exfil_chain", "high", a, category="collusion"),
            _f("static.shell.curl_pipe_sh", "critical", a, category="static"),
            _f("frontmatter.long_description", "medium", a, category="capability"),
        ])
        events = build_timeline(result)
        kinds = {e.kind for e in events}
        # drift, collusion, critical/high all appear; medium is excluded
        self.assertIn("drift", kinds)
        self.assertIn("collusion", kinds)
        self.assertIn("critical", kinds)

    def test_baseline_scans_appear_when_db_provided(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "y")
            db = root / "baseline.db"
            conn = open_db(db)
            save_baseline(conn, str(root), _project_artifacts(root))
            conn.close()
            events = build_timeline(ScanResult(), baseline_db=db, scan_root=str(root))
            self.assertTrue(any(e.kind == "scan" for e in events))


# --------------------------------------------------------------------------- #
# PagerDuty
# --------------------------------------------------------------------------- #

class PagerDutyTests(unittest.TestCase):
    def test_no_payload_below_threshold(self) -> None:
        a = _artifact()
        result = ScanResult()
        result.findings.append(_f("a", "low", a))
        payload = build_pagerduty_payload(result, routing_key="rk", threshold="high")
        self.assertIsNone(payload)

    def test_severity_mapping(self) -> None:
        a = _artifact()
        result = ScanResult()
        result.findings.append(_f("a", "critical", a))
        payload = build_pagerduty_payload(result, routing_key="rk", threshold="critical")
        self.assertEqual(payload["payload"]["severity"], "critical")
        result2 = ScanResult()
        result2.findings.append(_f("a", "high", a))
        payload2 = build_pagerduty_payload(result2, routing_key="rk", threshold="high")
        self.assertEqual(payload2["payload"]["severity"], "error")

    def test_dedup_key_default(self) -> None:
        a = _artifact()
        result = ScanResult()
        result.findings.append(_f("a", "critical", a))
        p = build_pagerduty_payload(result, routing_key="rk", threshold="high", host_id="dev-1")
        self.assertEqual(p["dedup_key"], "skillscan/dev-1/high")

    def test_send_uses_requester(self) -> None:
        captured: dict = {}
        def requester(url, body, headers):
            captured["url"] = url
            captured["body"] = body
            captured["headers"] = headers
        a = _artifact()
        result = ScanResult()
        result.findings.append(_f("a", "critical", a))
        os.environ["PAGERDUTY_ROUTING_KEY"] = "rk-test"
        try:
            n = send_pagerduty(result, threshold="critical", host_id="dev-1", requester=requester)
            self.assertGreater(n, 0)
        finally:
            del os.environ["PAGERDUTY_ROUTING_KEY"]
        self.assertEqual(captured["url"], "https://events.pagerduty.com/v2/enqueue")
        body = json.loads(captured["body"])
        self.assertEqual(body["routing_key"], "rk-test")

    def test_send_raises_without_key(self) -> None:
        os.environ.pop("PAGERDUTY_ROUTING_KEY", None)
        with self.assertRaises(RuntimeError):
            send_pagerduty(ScanResult())


# --------------------------------------------------------------------------- #
# Opsgenie
# --------------------------------------------------------------------------- #

class OpsgenieTests(unittest.TestCase):
    def test_priority_mapping(self) -> None:
        a = _artifact()
        result = ScanResult()
        result.findings.append(_f("a", "critical", a))
        p = build_opsgenie_payload(result, threshold="critical")
        self.assertEqual(p["priority"], "P1")
        result2 = ScanResult()
        result2.findings.append(_f("a", "medium", a))
        p2 = build_opsgenie_payload(result2, threshold="medium")
        self.assertEqual(p2["priority"], "P3")

    def test_no_payload_below_threshold(self) -> None:
        a = _artifact()
        result = ScanResult()
        result.findings.append(_f("a", "low", a))
        self.assertIsNone(build_opsgenie_payload(result, threshold="high"))

    def test_send_uses_geniekey_auth(self) -> None:
        captured: dict = {}
        def requester(url, body, headers):
            captured["url"] = url
            captured["headers"] = headers
        a = _artifact()
        result = ScanResult()
        result.findings.append(_f("a", "critical", a))
        os.environ["OPSGENIE_API_KEY"] = "key-123"
        try:
            send_opsgenie(result, threshold="critical", requester=requester)
        finally:
            del os.environ["OPSGENIE_API_KEY"]
        self.assertEqual(captured["url"], "https://api.opsgenie.com/v2/alerts")
        self.assertEqual(captured["headers"]["Authorization"], "GenieKey key-123")

    def test_send_eu_region_endpoint(self) -> None:
        captured: dict = {}
        def requester(url, body, headers):
            captured["url"] = url
        a = _artifact()
        result = ScanResult()
        result.findings.append(_f("a", "critical", a))
        os.environ["OPSGENIE_API_KEY"] = "key-123"
        try:
            send_opsgenie(
                result, threshold="critical",
                api_base="https://api.eu.opsgenie.com",
                requester=requester,
            )
        finally:
            del os.environ["OPSGENIE_API_KEY"]
        self.assertEqual(captured["url"], "https://api.eu.opsgenie.com/v2/alerts")


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #

class CliS7Tests(unittest.TestCase):
    def test_dashboard_includes_interactive_graph_and_timeline(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "demo")
            out = root / "dash.html"
            rc = main(["dashboard", str(root), "--no-user-global", "--db", str(root / "x.db"), "--output", str(out)])
            self.assertEqual(rc, 0)
            html = out.read_text()
            self.assertIn("Skill ↔ MCP ↔ tool graph", html)
            self.assertIn("ss-igraph", html)         # interactive graph div
            self.assertIn("Incident timeline", html)


if __name__ == "__main__":
    unittest.main()
