"""Alert connectors — Slack + Teams incoming webhooks.

Threshold-gated by severity. Use from the CLI via:
    skillscan scan ... --alert-slack URL --alert-threshold high
    skillscan scan ... --alert-teams URL --alert-threshold critical
"""

from skillscan.alerts.slack import build_slack_payload, send_slack
from skillscan.alerts.teams import build_teams_payload, send_teams

__all__ = ["build_slack_payload", "send_slack", "build_teams_payload", "send_teams"]
