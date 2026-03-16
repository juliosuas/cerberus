# 🛡️ Cerberus — Security-as-a-Service for SMBs

**Automated, AI-powered cybersecurity platform designed for small and medium businesses.**

Cerberus gives every business access to enterprise-grade security monitoring, vulnerability scanning, compliance checking, and breach detection — without needing a dedicated security team.

---

## Why Cerberus?

Most SMBs can't afford a $200K/year security engineer or a $50K/year SIEM platform. But they face the same threats as enterprises. **Cerberus closes that gap.**

- **Infrastructure Scanning** — Port scans, SSL/TLS grading, HTTP header audits, DNS checks, email security (SPF/DKIM/DMARC), subdomain takeover detection
- **Continuous Monitoring** — Uptime, SSL cert expiry, domain expiry, CVE matching, website defacement detection
- **Breach Monitoring** — Employee email breach checks, credential leak detection, domain mention monitoring
- **Compliance Scoring** — OWASP Top 10, SOC 2 readiness, GDPR exposure, PCI DSS basics, ISO 27001 gap analysis — each scored 0–100
- **AI Security Advisor** — Plain-language recommendations, prioritized by business impact, with remediation playbooks
- **Beautiful Dashboard** — Enterprise SaaS-quality dark theme UI with security scores, compliance radar, threat timelines
- **Multi-Tenant Ready** — Manage multiple clients from a single instance
- **Notifications** — Email, Slack, WhatsApp, and generic webhook integrations

---

## Quick Start

```bash
# Clone and configure
git clone <repo-url> cerberus && cd cerberus
cp .env.example .env
# Edit .env with your settings

# Run with Docker
docker-compose up -d

# Or run locally
make install
make seed    # Load demo data
make run     # Start on http://localhost:5000
```

Open [http://localhost:5000](http://localhost:5000) to see the dashboard.

---

## Architecture

```
cerberus/
├── core/           # Scanning, monitoring, compliance, AI advisor
├── api/            # Flask REST API + SQLite database
├── ui/             # Single-page dashboard (vanilla JS + Chart.js)
├── reports/        # Jinja2 report templates
├── notifications/  # Webhook, Email, Slack, WhatsApp
├── tests/          # Unit tests
└── seed/           # Demo seed data
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard` | Overall security score and stats |
| GET | `/api/scans` | List scans |
| POST | `/api/scans` | Trigger a new scan |
| GET | `/api/findings` | All findings (filterable) |
| GET | `/api/compliance` | Compliance scores |
| GET | `/api/breaches` | Breach monitoring results |
| GET | `/api/reports` | Generated reports |
| POST | `/api/targets` | Add monitored target |
| GET | `/api/health` | Health check |

## Configuration

All configuration is via environment variables (see `.env.example`):

- `CERBERUS_SECRET_KEY` — Flask secret key
- `CERBERUS_DB_PATH` — SQLite database path
- `CERBERUS_SCAN_INTERVAL` — Auto-scan interval in hours
- `SMTP_*` — Email notification settings
- `SLACK_WEBHOOK_URL` — Slack integration
- `WHATSAPP_WEBHOOK_URL` — WhatsApp integration
- `OPENAI_API_KEY` — For AI advisor (optional)

## Development

```bash
make install   # Install dependencies
make test      # Run tests
make lint      # Run linter
make seed      # Load seed data
make run       # Start dev server
```

## License

MIT — Built for businesses that deserve better security.
