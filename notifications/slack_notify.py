"""Slack notifications via incoming webhooks."""

import logging

import requests

from core.config import Config

logger = logging.getLogger("cerberus.notifications.slack")


def send_slack(text: str, blocks: list = None) -> bool:
    """Send a Slack notification via incoming webhook."""
    url = Config.SLACK_WEBHOOK_URL
    if not url:
        logger.debug("Slack webhook not configured")
        return False

    payload = {"text": text}
    if blocks:
        payload["blocks"] = blocks

    try:
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info("Slack notification sent")
        return True
    except requests.RequestException as e:
        logger.error(f"Slack notification failed: {e}")
        return False


def notify_finding(finding: dict) -> bool:
    """Send Slack alert for a security finding."""
    severity = finding.get("severity", "unknown").upper()
    emoji = {"CRITICAL": ":red_circle:", "HIGH": ":large_orange_circle:", "MEDIUM": ":large_yellow_circle:", "LOW": ":white_circle:"}.get(severity, ":grey_question:")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} {severity} Security Finding"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Category:*\n{finding.get('category', '')}"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
            ],
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{finding.get('title', '')}*\n{finding.get('description', '')}"},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Remediation:*\n{finding.get('remediation', '')}"},
        },
    ]

    return send_slack(f"{severity}: {finding.get('title', '')}", blocks)


def notify_scan_complete(target: str, score: int, findings: int) -> bool:
    """Send Slack notification for completed scan."""
    emoji = ":white_check_mark:" if score >= 80 else ":warning:" if score >= 60 else ":rotating_light:"

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} Scan Complete: {target}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Security Score:*\n{score}/100"},
                {"type": "mrkdwn", "text": f"*Findings:*\n{findings}"},
            ],
        },
    ]

    return send_slack(f"Scan complete for {target}: Score {score}/100", blocks)
