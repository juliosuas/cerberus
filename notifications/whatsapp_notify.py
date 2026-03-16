"""WhatsApp notifications via webhook (Jeffrey integration ready)."""

import logging

import requests

from core.config import Config

logger = logging.getLogger("cerberus.notifications.whatsapp")


def send_whatsapp(message: str) -> bool:
    """Send a WhatsApp notification via webhook."""
    url = Config.WHATSAPP_WEBHOOK_URL
    if not url:
        logger.debug("WhatsApp webhook not configured")
        return False

    payload = {
        "source": "cerberus",
        "message": message,
    }

    try:
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info("WhatsApp notification sent")
        return True
    except requests.RequestException as e:
        logger.error(f"WhatsApp notification failed: {e}")
        return False


def notify_critical(finding: dict) -> bool:
    """Send WhatsApp alert for critical findings."""
    severity = finding.get("severity", "unknown").upper()
    message = (
        f"🚨 *CERBERUS ALERT*\n\n"
        f"*Severity:* {severity}\n"
        f"*{finding.get('title', 'Security Alert')}*\n\n"
        f"{finding.get('description', '')}\n\n"
        f"*Action:* {finding.get('remediation', 'Review in Cerberus dashboard')}"
    )
    return send_whatsapp(message)


def notify_scan_summary(target: str, score: int, critical: int, high: int) -> bool:
    """Send WhatsApp scan summary."""
    emoji = "✅" if score >= 80 else "⚠️" if score >= 60 else "🔴"
    message = (
        f"{emoji} *Cerberus Scan Complete*\n\n"
        f"*Target:* {target}\n"
        f"*Score:* {score}/100\n"
        f"*Critical:* {critical} | *High:* {high}\n\n"
        f"Open Cerberus for details."
    )
    return send_whatsapp(message)
