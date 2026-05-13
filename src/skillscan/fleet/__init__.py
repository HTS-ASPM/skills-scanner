"""Fleet agent — periodic background scans posted to HTS-ASPM.

Snyk Agent Scan ships an MDM/CrowdStrike-deployable background mode;
this is the same shape — a thin loop that runs `skillscan scan` at an
interval and POSTs the result to a configurable ingest endpoint.

The runner is deliberately a function, not a daemon — wrapping it as a
LaunchAgent / systemd unit / Windows Service is left to the deployer
since packaging differs per OS.
"""

from skillscan.fleet.agent import AgentConfig, AgentResult, run_once, run_loop
from skillscan.fleet.poster import PostError, post_findings

__all__ = [
    "AgentConfig",
    "AgentResult",
    "PostError",
    "post_findings",
    "run_loop",
    "run_once",
]
