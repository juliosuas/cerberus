"""Generic webhook notifications."""

import hashlib
import hmac
import json
import logging

import requests

from core.config import Config

logger = logging.getLogger("cerberus.notifications.webhook")


def send_webhook(event: str, data: dict) -> bool:
    """Send a generic webhook notification."""
    url = Config.WEBHOOK_URL
    if not url:
        logger.debug("No webhook URL configured")
        return False

    payload = {
        "event": event,
        "source": "cerberus",
        "data": data,
    }

    headers = {"Content-Type": "application/json"}

    # Add HMAC signature if secret is configured
    if Config.WEBHOOK_SECRET:
        body = json.dumps(payload, sort_keys=True)
        signature = hmac.new(
            Config.WEBHOOK_SECRET.encode(),
            body.encode(),
            hashlib.sha256,
        ).hexdigest()
        headers["X-Cerberus-Signature"] = f"sha256={signature}"

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        resp.raise_for_status()
        logger.info(f"Webhook sent: {event}")
        return True
    except requests.RequestException as e:
        logger.error(f"Webhook failed: {e}")
        return False


def notify_finding(finding: dict) -> bool:
    """Send a webhook for a new finding."""
    return send_webhook("finding.new", finding)


def notify_scan_complete(target: str, findings_count: int, score: int) -> bool:
    """Send a webhook when a scan completes."""
    return send_webhook("scan.complete", {
        "target": target,
        "findings_count": findings_count,
        "security_score": score,
    })


def notify_breach(breach: dict) -> bool:
    """Send a webhook for a breach alert."""
    return send_webhook("breach.detected", breach)
