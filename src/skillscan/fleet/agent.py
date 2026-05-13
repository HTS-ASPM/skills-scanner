"""Fleet agent loop — periodic scan + post.

Two entry points:

  run_once(config)   -- single scan + post; returns AgentResult.
                        Use this from cron / launchd / systemd timers.
  run_loop(config)   -- in-process loop (blocking) for environments where
                        a long-running process is preferable. Honors
                        config.iterations (default = unbounded) and
                        config.sleeper to keep tests fast.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from skillscan.collusion import analyze as analyze_collusion
from skillscan.discover import (
    discover_claude_harness,
    discover_claude_skills,
    discover_mcp_servers,
)
from skillscan.fleet.poster import post_findings
from skillscan.models import ScanResult
from skillscan.rules import run_rules


@dataclass
class AgentConfig:
    aspm_url: str
    scan_root: Path = field(default_factory=lambda: Path.home())
    interval_seconds: int = 3600
    iterations: int | None = None       # None == unbounded
    aspm_token_env: str = "ASPM_TOKEN"
    host_id: str | None = None          # used as X-Skillscan-Host header
    siem_format: str | None = None      # "splunk" | "elastic" | "sentinel" | None
    siem_url: str | None = None
    sleeper: Callable[[float], None] = time.sleep
    poster: Callable[..., dict] | None = None  # injected for tests


@dataclass
class AgentResult:
    iteration: int
    artifacts: int
    findings: int
    posted: bool
    error: str | None = None


def run_once(config: AgentConfig) -> AgentResult:
    result = _scan(config.scan_root)
    posted, error = _post(config, result)
    return AgentResult(
        iteration=1,
        artifacts=len(result.artifacts),
        findings=len(result.findings),
        posted=posted,
        error=error,
    )


def run_loop(config: AgentConfig) -> list[AgentResult]:
    results: list[AgentResult] = []
    iteration = 0
    while True:
        iteration += 1
        result = _scan(config.scan_root)
        posted, error = _post(config, result)
        results.append(AgentResult(
            iteration=iteration,
            artifacts=len(result.artifacts),
            findings=len(result.findings),
            posted=posted,
            error=error,
        ))
        if config.iterations is not None and iteration >= config.iterations:
            break
        config.sleeper(config.interval_seconds)
    return results


def _scan(root: Path) -> ScanResult:
    result = ScanResult()
    result.artifacts.extend(discover_claude_skills(root))
    result.artifacts.extend(discover_claude_harness(root))
    result.artifacts.extend(discover_mcp_servers(root))
    result.findings.extend(run_rules(result.artifacts))
    result.findings.extend(analyze_collusion(result.artifacts, result.findings))
    return result


def _post(config: AgentConfig, result: ScanResult) -> tuple[bool, str | None]:
    poster = config.poster or post_findings
    try:
        poster(
            url=config.aspm_url,
            result=result,
            token_env=config.aspm_token_env,
            host_id=config.host_id,
            siem_format=config.siem_format,
            siem_url=config.siem_url,
        )
    except Exception as exc:  # noqa: BLE001 — agent must not crash on transport
        return False, str(exc)
    return True, None
