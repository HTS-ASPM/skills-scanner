"""Tests for S4 — fleet agent + SIEM connectors + JS/TS deep scan."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from skillscan.discover import discover_claude_skills
from skillscan.fleet import AgentConfig, run_loop, run_once
from skillscan.fleet.poster import post_findings
from skillscan.models import ScanResult
from skillscan.rules import deep_scan_js
from skillscan.siem import format_for_siem


def _project_skill(root: Path, name: str, *, frontmatter: str = "", files: dict[str, str] | None = None) -> None:
    skill_dir = root / ".claude" / "skills" / name
    skill_dir.mkdir(parents=True)
    if not frontmatter:
        frontmatter = f"name: {name}\ndescription: a test skill"
    (skill_dir / "SKILL.md").write_text(f"---\n{frontmatter}\n---\nbody\n", encoding="utf-8")
    for rel, content in (files or {}).items():
        target = skill_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _project_artifacts(root: Path):
    return [a for a in discover_claude_skills(root) if str(a.path).startswith(str(root))]


class JsDeepScanTests(unittest.TestCase):
    def test_eval_in_js(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "ev", files={"r.js": "const x = eval('1+1');\n"})
            findings = deep_scan_js.run(_project_artifacts(root)[0])
            self.assertTrue(any(f.rule_id == "deep.js.eval_or_function" for f in findings))

    def test_child_process_exec(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(
                root, "cp",
                files={"r.ts": "import cp from 'child_process';\ncp.execSync('ls')\n"},
            )
            findings = deep_scan_js.run(_project_artifacts(root)[0])
            ids = {f.rule_id for f in findings}
            self.assertIn("deep.js.child_process_exec", ids)
            sev = next(f.severity for f in findings if f.rule_id == "deep.js.child_process_exec")
            self.assertEqual(sev, "high")

    def test_buffer_b64_then_eval_critical(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(
                root, "obfusc",
                files={"r.js": "const p = Buffer.from(payload, 'base64').toString();\neval(p);\n"},
            )
            findings = deep_scan_js.run(_project_artifacts(root)[0])
            crit = [f for f in findings if f.rule_id == "deep.js.buffer_b64_then_eval"]
            self.assertEqual(len(crit), 1)
            self.assertEqual(crit[0].severity, "critical")

    def test_template_literal_fetch(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(
                root, "fetch",
                files={"r.ts": "const url = `https://api.${host}/x`;\nawait fetch(`https://api.${host}/x`);\n"},
            )
            findings = deep_scan_js.run(_project_artifacts(root)[0])
            self.assertTrue(any(f.rule_id == "deep.js.fetch_dynamic_url" for f in findings))


class SiemFormatterTests(unittest.TestCase):
    def _result_with_one_finding(self) -> ScanResult:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "f", frontmatter='name: f\ndescription: x\nallowed-tools: "*"')
            result = ScanResult()
            from skillscan.rules import run_rules
            result.artifacts.extend(_project_artifacts(root))
            result.findings.extend(run_rules(result.artifacts))
        return result

    def test_splunk_event_envelope(self) -> None:
        result = self._result_with_one_finding()
        events = format_for_siem(result, "splunk", host_id="dev-machine")
        self.assertTrue(events)
        for ev in events:
            self.assertEqual(ev["sourcetype"], "skillscan:finding")
            self.assertEqual(ev["host"], "dev-machine")
            self.assertIn("event", ev)
            self.assertIn("rule_id", ev["event"])

    def test_elastic_ecs_severity_mapping(self) -> None:
        result = self._result_with_one_finding()
        events = format_for_siem(result, "elastic", host_id="dev-machine")
        for ev in events:
            self.assertIn("event", ev)
            self.assertIn(ev["event"]["risk_score_norm"], {"critical", "high", "medium", "low", "info"})
            # critical maps to 80 in our table
            if ev["event"]["risk_score_norm"] == "critical":
                self.assertEqual(ev["event"]["severity"], 80)

    def test_sentinel_field_naming(self) -> None:
        result = self._result_with_one_finding()
        rows = format_for_siem(result, "sentinel", host_id="dev-machine")
        for row in rows:
            self.assertIn("RuleId_s", row)
            self.assertIn("Severity_s", row)

    def test_unknown_format_raises(self) -> None:
        with self.assertRaises(ValueError):
            format_for_siem(ScanResult(), "qradar")


class FleetAgentTests(unittest.TestCase):
    def test_run_once_posts_and_returns_result(self) -> None:
        captured: list[dict] = []
        def fake_poster(*, url, result, token_env, host_id, siem_format, siem_url):
            captured.append({"url": url, "findings": len(result.findings), "host_id": host_id})
            return {"status": 202}

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(
                root, "wild",
                frontmatter='name: wild\ndescription: x\nallowed-tools: "*"',
            )
            config = AgentConfig(
                aspm_url="https://aspm.example/ingest",
                scan_root=root,
                host_id="dev-1",
                poster=fake_poster,
            )
            result = run_once(config)
            self.assertTrue(result.posted)
            self.assertGreater(result.findings, 0)
            self.assertEqual(captured[0]["url"], "https://aspm.example/ingest")
            self.assertEqual(captured[0]["host_id"], "dev-1")

    def test_run_loop_honors_iterations(self) -> None:
        sleeps: list[float] = []
        def fake_poster(**kw):
            return {"status": 202}

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = AgentConfig(
                aspm_url="https://aspm.example/ingest",
                scan_root=root,
                interval_seconds=1,
                iterations=3,
                poster=fake_poster,
                sleeper=lambda s: sleeps.append(s),
            )
            results = run_loop(config)
            self.assertEqual(len(results), 3)
            self.assertEqual(sleeps, [1, 1])  # sleeps after iters 1 and 2, not after 3

    def test_post_failure_does_not_crash_loop(self) -> None:
        def failing_poster(**kw):
            raise RuntimeError("boom")
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = AgentConfig(
                aspm_url="https://aspm.example/ingest",
                scan_root=root,
                interval_seconds=0,
                iterations=1,
                poster=failing_poster,
            )
            result = run_once(config)
            self.assertFalse(result.posted)
            self.assertIn("boom", result.error or "")


class PostFindingsTransportTests(unittest.TestCase):
    def test_post_uses_bearer_and_host_header(self) -> None:
        captured: dict = {}

        def requester(url, body, headers):
            captured["url"] = url
            captured["body"] = body
            captured["headers"] = headers
            return {"status": 200}

        import os
        os.environ["ASPM_TOKEN"] = "tok-xyz"
        try:
            post_findings(
                url="https://aspm.example/ingest",
                result=ScanResult(),
                host_id="dev-2",
                requester=requester,
            )
        finally:
            os.environ.pop("ASPM_TOKEN", None)
        self.assertEqual(captured["headers"]["Authorization"], "Bearer tok-xyz")
        self.assertEqual(captured["headers"]["X-Skillscan-Host"], "dev-2")
        # body must be valid JSON
        json.loads(captured["body"])

    def test_post_mirrors_to_siem(self) -> None:
        captured_urls: list[str] = []

        def requester(url, body, headers):
            captured_urls.append(url)
            return {"status": 200}

        post_findings(
            url="https://aspm.example/ingest",
            result=ScanResult(),
            siem_format="elastic",
            siem_url="https://elastic.example/_bulk",
            requester=requester,
        )
        self.assertEqual(captured_urls, ["https://aspm.example/ingest", "https://elastic.example/_bulk"])


if __name__ == "__main__":
    unittest.main()
