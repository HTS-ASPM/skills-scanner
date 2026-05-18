"""Alert connectors — Slack + Teams incoming webhooks.

Threshold-gated by severity. Use from the CLI via:
    skillscan scan ... --alert-slack URL --alert-threshold high
    skillscan scan ... --alert-teams URL --alert-threshold critical
"""

from skillscan.alerts.opsgenie import build_opsgenie_payload, send_opsgenie
from skillscan.alerts.pagerduty import build_pagerduty_payload, send_pagerduty
from skillscan.alerts.slack import build_slack_payload, send_slack
from skillscan.alerts.teams import build_teams_payload, send_teams

__all__ = [
    "build_opsgenie_payload",
    "build_pagerduty_payload",
    "build_slack_payload",
    "build_teams_payload",
    "send_opsgenie",
    "send_pagerduty",
    "send_slack",
    "send_teams",
]
