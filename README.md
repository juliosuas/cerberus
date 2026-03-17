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

## 📊 SMB Security Scoring Methodology

Cerberus uses a proprietary scoring system designed specifically for small and medium businesses — not just a dumbed-down enterprise framework.

### Overall Security Score (0-100)

The headline score is a weighted composite of five security dimensions:

| Dimension | Weight | What It Measures |
|-----------|--------|-----------------|
| 🛡️ Infrastructure | 30% | Port exposure, SSL/TLS grade, HTTP headers, DNS security |
| 🔐 Authentication | 25% | Password policies, MFA adoption, SSO configuration, session management |
| 📋 Compliance | 20% | Framework coverage (OWASP, SOC 2, GDPR, PCI DSS, ISO 27001) |
| 📡 Monitoring | 15% | Uptime tracking, certificate expiry, CVE exposure, breach monitoring |
| 👥 Human Factor | 10% | Employee email exposure, breach history, security awareness indicators |

### Score Interpretation for SMBs

| Score Range | Rating | What It Means | Typical Action |
|-------------|--------|---------------|----------------|
| 90-100 | 🟢 Excellent | Enterprise-grade security posture | Maintain and monitor |
| 75-89 | 🟢 Good | Strong fundamentals, minor gaps | Address medium findings |
| 60-74 | 🟡 Fair | Common SMB level — fixable gaps | Prioritize critical fixes |
| 40-59 | 🟠 Poor | Significant exposure — action needed | Immediate remediation plan |
| 0-39 | 🔴 Critical | High breach risk | Emergency assessment |

### Infrastructure Scoring Breakdown

Each infrastructure check contributes to the dimension score:

| Check | Max Points | Scoring Criteria |
|-------|-----------|-----------------|
| Port Exposure | 25 | 25 = only needed ports open; -3 per unnecessary exposed port |
| SSL/TLS Grade | 25 | A+ = 25, A = 22, B = 15, C = 8, D/F = 0 |
| HTTP Security Headers | 20 | +4 per header: HSTS, CSP, X-Frame, X-Content-Type, Referrer-Policy |
| DNS Security | 15 | SPF (+5), DKIM (+5), DMARC enforce (+5) |
| Subdomain Hygiene | 15 | 15 = no dangling CNAMEs; -5 per takeover-vulnerable subdomain |

### Compliance Scoring Approach

Each compliance framework is scored independently (0-100), then contributes to the composite:

#### OWASP Top 10 Assessment
- Each of the 10 categories is tested with automated checks
- Pass/Fail/Partial scoring per category
- Score = (Passed × 10) + (Partial × 5)

#### SOC 2 Readiness
- Maps to Trust Service Criteria (Security, Availability, Confidentiality)
- Automated checks cover ~40% of controls (infrastructure-testable)
- Remaining 60% flagged as "requires manual review" with guidance

#### GDPR Exposure
- Cookie consent detection
- Privacy policy presence and completeness
- Data processing transparency
- Cross-border transfer indicators

#### PCI DSS Basics
- Cardholder data environment exposure
- Encryption in transit verification
- Access control assessment
- Network segmentation checks

#### ISO 27001 Gap Analysis
- Maps findings to Annex A controls
- Identifies implemented vs. missing controls
- Generates prioritized implementation roadmap

### Scoring vs. Enterprise Tools

| Aspect | Cerberus | Enterprise SIEM/Scanner |
|--------|----------|------------------------|
| Cost to implement | Free (self-hosted) | $50K-$500K/year |
| Time to first score | 5 minutes | Days to weeks |
| SMB relevance | ✅ Built for SMBs | Designed for enterprises |
| Actionable output | Plain-language fixes | Technical jargon |
| Continuous monitoring | ✅ Included | Additional cost |
| Multi-framework | 5 frameworks | Varies by license |

---

## 🖥️ Platform Compatibility

| Platform | Architecture | Status | Notes |
|----------|-------------|--------|-------|
| Ubuntu 22.04+ | x86_64, ARM64 | ✅ Full | Recommended for production |
| Debian 12+ | x86_64, ARM64 | ✅ Full | Fully tested |
| macOS 13+ | ARM64, x86_64 | ✅ Full | Development and small deployments |
| Windows 11 | x86_64 | ⚠️ Partial | Docker recommended |
| Docker | Any | ✅ Full | `docker-compose up -d` — production ready |
| Raspberry Pi OS | ARM64 | ✅ Full | Perfect for small office deployment |
| Alpine Linux | x86_64, ARM64 | ✅ Full | Minimal container base |

### Database Compatibility

| Database | Status | Notes |
|----------|--------|-------|
| SQLite | ✅ Default | Zero-config, perfect for single-instance |
| PostgreSQL | ✅ Supported | Recommended for multi-tenant / MSP |
| MySQL/MariaDB | ⚠️ Planned | Coming in next release |

### Notification Integration Compatibility

| Platform | Protocol | Status |
|----------|----------|--------|
| Email (SMTP) | SMTP/TLS | ✅ Full |
| Slack | Webhook | ✅ Full |
| WhatsApp | API | ✅ Full |
| Microsoft Teams | Webhook | ✅ Full |
| Discord | Webhook | ✅ Full |
| PagerDuty | API | ⚠️ Planned |
| Generic Webhook | HTTP POST | ✅ Full |

---

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

---
### 🌱 Also check out
**[AI Garden](https://github.com/juliosuas/ai-garden)** — A living world built exclusively by AI agents. Watch it grow.
