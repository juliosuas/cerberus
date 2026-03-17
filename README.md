<p align="center">
  <h1 align="center">🛡️ Cerberus</h1>
  <p align="center"><strong>Security-as-a-Service for Small & Medium Businesses</strong></p>
  <p align="center">
    Enterprise-grade cybersecurity — without the enterprise price tag.
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Docker-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/OWASP-Top%2010-orange?logo=owasp" alt="OWASP">
  <img src="https://img.shields.io/badge/SOC%202-Ready-blueviolet" alt="SOC 2">
  <img src="https://img.shields.io/badge/status-active-brightgreen" alt="Status">
</p>

---

## The Problem

Most SMBs can't afford a $200K/year security engineer or a $50K/year SIEM. But they face the **same threats** as enterprises — ransomware, phishing, data breaches, compliance fines.

**Cerberus closes that gap.** One platform. Automated scanning. AI-driven recommendations. Beautiful dashboards. Deploy in minutes.

---

## ✨ Features

- 🔍 **Infrastructure Scanning** — Port scans, SSL/TLS grading, HTTP header audits, DNS checks, SPF/DKIM/DMARC validation, subdomain takeover detection
- 📡 **Continuous Monitoring** — Uptime, SSL cert expiry, domain expiry, CVE matching, website defacement detection
- 🚨 **Breach Monitoring** — Employee email breach checks, credential leak detection, domain mention monitoring across paste sites
- 📊 **Compliance Scoring** — OWASP Top 10, SOC 2 readiness, GDPR exposure, PCI DSS basics, ISO 27001 gap analysis — each scored 0–100
- 🤖 **AI Security Advisor** — Plain-language recommendations prioritized by business impact, with step-by-step remediation playbooks
- 🎨 **Enterprise Dashboard** — Dark-themed SaaS-quality UI with security scores, compliance radar, threat timelines
- 👥 **Multi-Tenant** — Manage multiple clients from a single instance (MSP-ready)
- 🔔 **Notifications** — Email, Slack, WhatsApp, and generic webhook integrations

---

## 🚀 Quick Start

```bash
git clone https://github.com/juliosuas/cerberus.git && cd cerberus
cp .env.example .env          # Configure your settings
make install && make seed      # Install deps + load demo data
make run                       # → http://localhost:5000
```

> **Docker:** `docker-compose up -d` and open [localhost:5000](http://localhost:5000)

---

## 📸 Screenshots

<p align="center">
  <em>Screenshots coming soon — dashboard, compliance radar, scan results, AI advisor</em>
</p>

<!-- 
![Dashboard](docs/screenshots/dashboard.png)
![Compliance Radar](docs/screenshots/compliance.png)
![Scan Results](docs/screenshots/scan-results.png)
-->

---

## 🏗️ Architecture

```
cerberus/
├── core/           # Scanning, monitoring, compliance, AI advisor engines
├── api/            # Flask REST API + SQLite database
├── ui/             # Single-page dashboard (vanilla JS + Chart.js)
├── reports/        # Jinja2 report templates (PDF/HTML)
├── notifications/  # Webhook, Email, Slack, WhatsApp integrations
├── tests/          # Unit + integration tests
└── seed/           # Demo seed data
```

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/dashboard` | Overall security score and stats |
| `GET` | `/api/scans` | List all scans |
| `POST` | `/api/scans` | Trigger a new scan |
| `GET` | `/api/findings` | All findings (filterable by severity, type) |
| `GET` | `/api/compliance` | Compliance scores across frameworks |
| `GET` | `/api/breaches` | Breach monitoring results |
| `GET` | `/api/reports` | Generated reports |
| `POST` | `/api/targets` | Add a monitored target |
| `GET` | `/api/health` | Health check |

## ⚙️ Configuration

All configuration via environment variables (see `.env.example`):

| Variable | Description |
|----------|-------------|
| `CERBERUS_SECRET_KEY` | Flask secret key |
| `CERBERUS_DB_PATH` | SQLite database path |
| `CERBERUS_SCAN_INTERVAL` | Auto-scan interval (hours) |
| `SMTP_*` | Email notification settings |
| `SLACK_WEBHOOK_URL` | Slack integration |
| `WHATSAPP_WEBHOOK_URL` | WhatsApp integration |
| `OPENAI_API_KEY` | AI advisor (optional) |

## 🏁 Compared to Alternatives

| Feature | Cerberus | Qualys | Tenable | DIY Scripts |
|---------|----------|--------|---------|-------------|
| SMB-friendly pricing | ✅ Free/OSS | ❌ $$$$ | ❌ $$$$ | ✅ Free |
| AI-powered recommendations | ✅ | ❌ | ❌ | ❌ |
| Compliance scoring | ✅ 5 frameworks | ✅ | ✅ | ❌ |
| Multi-tenant | ✅ | ✅ | ✅ | ❌ |
| Self-hosted | ✅ | ❌ | ❌ | ✅ |
| Setup time | ~5 min | Days | Days | Weeks |

## 🛠️ Development

```bash
make install   # Install dependencies
make test      # Run test suite
make lint      # Run linter
make seed      # Load seed data
make run       # Start dev server
```

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please read our issues for areas where help is needed. Bug reports and feature requests are also appreciated!

## ⚖️ Legal Disclaimer

Cerberus is designed for **authorized security assessment only**. Users are responsible for ensuring they have proper authorization before scanning any systems or networks. The authors assume no liability for misuse or damages. Always comply with applicable laws and regulations.

## 📄 License

MIT — Built for businesses that deserve better security.

---

<p align="center">
  <strong>Cerberus</strong> — Because every business deserves a guard dog. 🐕
</p>
