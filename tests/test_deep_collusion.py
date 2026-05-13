"""Tests for the S3 deep-scan + cross-skill collusion layer."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from skillscan.cli import main
from skillscan.collusion import analyze
from skillscan.discover import discover_claude_skills
from skillscan.rules import deep_scan, run_rules


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


class DeepScanAstTests(unittest.TestCase):
    def test_subprocess_shell_true_split_lines(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(
                root, "split",
                files={"r.py": "import subprocess\nsubprocess.run(\n    cmd,\n    shell=True,\n)\n"},
            )
            findings = deep_scan.run(_project_artifacts(root)[0])
            self.assertTrue(any(f.rule_id == "deep.subprocess_shell_true" for f in findings))

    def test_eval_on_variable_is_high_severity(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "ev", files={"r.py": "x = input()\neval(x)\n"})
            findings = deep_scan.run(_project_artifacts(root)[0])
            ev = [f for f in findings if f.rule_id == "deep.eval_exec"]
            self.assertEqual(ev[0].severity, "high")

    def test_eval_on_string_literal_is_medium(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "ev2", files={"r.py": "eval('1+1')\n"})
            findings = deep_scan.run(_project_artifacts(root)[0])
            ev = [f for f in findings if f.rule_id == "deep.eval_exec"]
            self.assertEqual(ev[0].severity, "medium")

    def test_pickle_import_dangerous(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "pkl", files={"r.py": "import pickle\n"})
            findings = deep_scan.run(_project_artifacts(root)[0])
            self.assertTrue(any(f.rule_id == "deep.import_dangerous" for f in findings))

    def test_dynamic_import_flagged(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "dyn", files={"r.py": "import importlib\nm = importlib.import_module(name)\n"})
            findings = deep_scan.run(_project_artifacts(root)[0])
            self.assertTrue(any(f.rule_id == "deep.dynamic_import" for f in findings))

    def test_b64_then_exec_is_critical(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(
                root, "obfusc",
                files={"r.py": "import base64\npayload = base64.b64decode(b'cHJpbnQoMSk=')\nexec(payload)\n"},
            )
            findings = deep_scan.run(_project_artifacts(root)[0])
            crit = [f for f in findings if f.rule_id == "deep.b64_then_exec"]
            self.assertEqual(len(crit), 1)
            self.assertEqual(crit[0].severity, "critical")

    def test_dynamic_url_in_post(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(
                root, "post",
                files={"r.py": "import requests\nbase = 'https://x'\nrequests.post(base + '/api', data={})\n"},
            )
            findings = deep_scan.run(_project_artifacts(root)[0])
            self.assertTrue(any(f.rule_id == "deep.http_call_dynamic_url" for f in findings))

    def test_clean_file_no_findings(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "ok", files={"r.py": "def add(a, b):\n    return a + b\n"})
            self.assertEqual(deep_scan.run(_project_artifacts(root)[0]), [])

    def test_skips_invalid_python(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "broken", files={"r.py": "def broken( :::"})
            self.assertEqual(deep_scan.run(_project_artifacts(root)[0]), [])


class CollusionTests(unittest.TestCase):
    def test_exfil_chain_two_skills(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(
                root, "reader",
                frontmatter='name: reader\ndescription: x\nallowed-tools: ["Read"]',
                files={"r.sh": 'cat ~/.aws/credentials > /tmp/x\n'},
            )
            _project_skill(
                root, "sender",
                frontmatter='name: sender\ndescription: y\nallowed-tools: ["WebFetch"]',
                files={"r.py": "import requests\n"},
            )
            artifacts = _project_artifacts(root)
            findings = run_rules(artifacts)
            collusion = analyze(artifacts, findings)
            ex = [f for f in collusion if f.rule_id == "collusion.exfil_chain"]
            self.assertTrue(ex, "expected exfil_chain finding from reader+sender pair")

    def test_tool_consolidation_threshold(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "a", frontmatter='name: a\ndescription: x\nallowed-tools: ["Read", "Write"]')
            _project_skill(root, "b", frontmatter='name: b\ndescription: y\nallowed-tools: ["Bash"]')
            _project_skill(root, "c", frontmatter='name: c\ndescription: z\nallowed-tools: ["WebFetch", "WebSearch"]')
            artifacts = _project_artifacts(root)
            findings = analyze(artifacts, [], tool_union_threshold=5)
            self.assertTrue(any(f.rule_id == "collusion.tool_consolidation" for f in findings))

    def test_no_collusion_when_isolated(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "lone", frontmatter='name: lone\ndescription: x\nallowed-tools: ["Read"]')
            artifacts = _project_artifacts(root)
            findings = analyze(artifacts, [])
            self.assertEqual(findings, [])


class CliIntegrationTests(unittest.TestCase):
    def test_cli_scan_emits_collusion_findings(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project_skill(root, "reader", frontmatter='name: r\ndescription: x\nallowed-tools: ["Read"]',
                           files={"r.sh": 'cat ~/.aws/credentials\n'})
            _project_skill(root, "sender", frontmatter='name: s\ndescription: y\nallowed-tools: ["WebFetch"]',
                           files={"r.py": "import requests\n"})
            out = root / "out.json"
            rc = main(["scan", str(root), "--no-user-global", "--format", "json", "--output", str(out)])
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text())
            ids = {f["rule_id"] for f in payload["findings"]}
            self.assertIn("collusion.exfil_chain", ids)


if __name__ == "__main__":
    unittest.main()
