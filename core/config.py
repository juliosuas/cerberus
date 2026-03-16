"""Cerberus configuration loader."""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("CERBERUS_SECRET_KEY", "dev-secret-key")
    DB_PATH = os.getenv("CERBERUS_DB_PATH", "cerberus.db")
    SCAN_INTERVAL_HOURS = int(os.getenv("CERBERUS_SCAN_INTERVAL", "24"))

    # SMTP
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASS = os.getenv("SMTP_PASS", "")
    SMTP_FROM = os.getenv("SMTP_FROM", "cerberus@localhost")
    ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "")

    # Slack
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

    # WhatsApp
    WHATSAPP_WEBHOOK_URL = os.getenv("WHATSAPP_WEBHOOK_URL", "")

    # AI
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

    # Webhook
    WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")
    WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
