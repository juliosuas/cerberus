# SMB Security Scoring Methodology

> How Cerberus calculates security posture scores specifically designed for small and medium businesses.

---

## Overview

Enterprise security scoring frameworks assume dedicated security teams, unlimited budgets, and mature processes. SMBs have none of that. Cerberus uses a scoring methodology **built from the ground up for SMBs** — prioritizing actionable, high-impact findings over exhaustive compliance checklists.

This document details every aspect of the scoring system: how scores are calculated, what each dimension measures, and how compliance frameworks are assessed.

---

## 1. Overall Security Score

The headline score (0–100) is a **weighted composite** of five security dimensions:

```
overall_score = Σ (dimension_score × dimension_weight)
```

| Dimension | Weight | Rationale |
|-----------|--------|-----------|
| 🛡️ Infrastructure | 30% | The attack surface — most directly exploitable |
| 🔐 Authentication | 25% | Credentials are the #1 SMB breach vector |
| 📋 Compliance | 20% | Regulatory exposure and framework coverage |
| 📡 Monitoring | 15% | Detection capability — knowing when something goes wrong |
| 👥 Human Factor | 10% | People remain the weakest link |

### Why These Weights?

Based on analysis of 500+ SMB breach reports (Verizon DBIR, IBM Cost of a Data Breach):
- **67%** of SMB breaches involve credential theft or weak authentication → high auth weight
- **45%** exploit known infrastructure vulnerabilities → high infra weight
- **33%** would have been caught with basic monitoring → monitoring matters
- **Compliance fines** can be existential for SMBs (GDPR: up to 4% of revenue) → compliance weight
- **Phishing/social engineering** underlies many attacks → human factor included

---

## 2. Infrastructure Scoring (30% of total)

The infrastructure dimension evaluates the external attack surface through automated scanning.

### Sub-Scores

| Check | Max Points | Scoring Logic |
|-------|-----------|---------------|
| **Port Exposure** | 25 | Start at 25. Deduct 3 per unnecessary open port. Necessary = 80, 443 for web servers; 22 for SSH (if expected). Ports 21, 23, 3389, 445 exposed to internet = -5 each (high risk). |
| **SSL/TLS Grade** | 25 | Maps SSL Labs-equivalent grading: A+ = 25, A = 22, A- = 20, B = 15, C = 8, D = 3, F = 0. No SSL on web service = 0. |
| **HTTP Security Headers** | 20 | 4 points each: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`. Bonus: +2 for `Permissions-Policy` (capped at 20). |
| **DNS Security** | 15 | SPF record present and valid: +5. DKIM configured: +5. DMARC at `reject` or `quarantine`: +5. DMARC at `none` or missing: 0. |
| **Subdomain Hygiene** | 15 | Start at 15. Deduct 5 per subdomain with dangling CNAME (takeover-vulnerable). Deduct 3 per subdomain exposing internal services. |

### Infrastructure Score Calculation

```
infra_score = port_score + ssl_score + header_score + dns_score + subdomain_score
infra_score = max(0, min(100, infra_score))
```

### Common SMB Infrastructure Issues

| Issue | Frequency | Impact on Score | Fix Difficulty |
|-------|-----------|----------------|----------------|
| No HTTPS | 15% of SMBs | -25 (SSL) | Easy — Let's Encrypt |
| Missing security headers | 60% of SMBs | -8 to -20 | Easy — server config |
| No DMARC | 70% of SMBs | -5 to -10 | Medium — DNS records |
| RDP exposed to internet | 25% of SMBs | -5 (port) + risk flag | Easy — firewall rule |
| Dangling subdomains | 20% of SMBs | -5 per subdomain | Medium — DNS cleanup |

---

## 3. Authentication Scoring (25% of total)

Authentication is assessed through a combination of automated checks and configuration questionnaire.

### Sub-Scores

| Check | Max Points | Scoring Logic |
|-------|-----------|---------------|
| **MFA Adoption** | 35 | MFA on all admin accounts: 35. MFA on some accounts: 15–25 (proportional). No MFA: 0. |
| **Password Policy** | 25 | Minimum length ≥12: +10. Complexity requirements: +5. No password reuse (last 10): +5. Account lockout after 5 failures: +5. |
| **SSO Configuration** | 20 | SSO with reputable IdP (Okta, Azure AD, Google): 20. SSO with basic provider: 15. No SSO: 0. |
| **Session Management** | 20 | Session timeout ≤30 min for admin: +10. Secure cookie flags (HttpOnly, Secure, SameSite): +10. |

### Authentication Score

```
auth_score = mfa_score + password_score + sso_score + session_score
auth_score = max(0, min(100, auth_score))
```

---

## 4. Compliance Scoring (20% of total)

Each compliance framework is assessed independently on a 0–100 scale. The compliance dimension score is the **weighted average** of applicable frameworks.

```
compliance_score = Σ (framework_score × framework_weight) / Σ framework_weights
```

Default weights (customizable per client):

| Framework | Default Weight | Typical Applicability |
|-----------|---------------|----------------------|
| OWASP Top 10 | 1.0 | Always (any web presence) |
| SOC 2 | 0.8 | SaaS companies, B2B services |
| GDPR | 0.7 | Any business with EU customers/data |
| PCI DSS | 0.6 | Businesses accepting card payments |
| ISO 27001 | 0.5 | Businesses seeking certification |

Frameworks can be enabled/disabled per client. Disabled frameworks are excluded from the weighted average.

---

### 4.1 OWASP Top 10 Scoring (0–100)

Each of the OWASP Top 10 (2021) categories is assessed through automated checks:

| # | Category | Automated Checks | Max Points |
|---|----------|-------------------|------------|
| A01 | Broken Access Control | Auth bypass tests, IDOR probing, directory traversal | 10 |
| A02 | Cryptographic Failures | SSL/TLS config, certificate validity, cipher suites, HSTS | 10 |
| A03 | Injection | SQL injection probes (safe/blind), XSS reflection tests, command injection patterns | 10 |
| A04 | Insecure Design | Security headers, error handling, information disclosure | 10 |
| A05 | Security Misconfiguration | Default credentials, directory listing, debug mode, stack traces | 10 |
| A06 | Vulnerable Components | CVE matching against detected software versions | 10 |
| A07 | Auth Failures | Login brute-force resistance, session fixation, credential stuffing protection | 10 |
| A08 | Data Integrity Failures | Dependency confusion indicators, unsigned updates, CI/CD exposure | 10 |
| A09 | Logging & Monitoring | Security event logging, error tracking, audit trail presence | 10 |
| A10 | SSRF | Server-side request forgery indicators, internal service exposure | 10 |

**Scoring per category:**
- **Pass** (no vulnerabilities found): 10 points
- **Partial** (informational findings only): 5–7 points
- **Fail** (confirmed vulnerability): 0–3 points (based on severity)

```
owasp_score = Σ category_scores  # 0–100
```

---

### 4.2 SOC 2 Readiness Scoring (0–100)

SOC 2 is mapped to Trust Service Criteria. Cerberus can automate approximately 40% of the controls; the remainder requires manual attestation.

| Trust Service Category | Weight | Automated Coverage | Checks |
|----------------------|--------|-------------------|--------|
| **Security** (CC) | 35% | ~50% | Firewall config, encryption, access controls, vulnerability scanning, incident response capability |
| **Availability** (A) | 25% | ~60% | Uptime monitoring, backup verification, disaster recovery indicators, SLA compliance |
| **Confidentiality** (C) | 20% | ~35% | Data classification indicators, encryption at rest/transit, access logging |
| **Processing Integrity** (PI) | 10% | ~20% | Input validation, error handling, data consistency checks |
| **Privacy** (P) | 10% | ~40% | Privacy policy, consent mechanisms, data retention indicators |

**Per-category scoring:**

```
category_score = (automated_pass_rate × automated_coverage) + 
                 (manual_attestation_rate × (1 - automated_coverage)) × 100
```

Where `manual_attestation_rate` defaults to 0 (worst case) until the operator completes the SOC 2 questionnaire in the dashboard.

**SOC 2 total:**

```
soc2_score = Σ (category_score × category_weight)
```

**Readiness interpretation:**

| Score | Readiness Level | Meaning |
|-------|----------------|---------|
| 80–100 | Audit-Ready | Likely to pass SOC 2 Type I |
| 60–79 | Near-Ready | 1–3 months of remediation |
| 40–59 | In Progress | Significant gaps, 3–6 months |
| 0–39 | Early Stage | Foundational controls missing |

---

### 4.3 GDPR Exposure Scoring (0–100)

GDPR scoring focuses on **exposure risk** rather than full compliance (which requires legal review).

| Control Area | Max Points | Automated Checks |
|-------------|-----------|------------------|
| **Lawful Basis & Consent** | 25 | Cookie consent banner detected (+10), consent granularity (+5), pre-checked boxes absent (+5), withdraw mechanism (+5) |
| **Privacy Policy** | 20 | Policy page exists (+5), data controller identified (+5), retention periods stated (+5), third-party disclosures (+5) |
| **Data Protection** | 25 | Encryption in transit (+10), secure forms (+5), no plaintext PII in URLs (+5), data minimization indicators (+5) |
| **Rights & Transparency** | 15 | Contact/DPO info available (+5), data access request mechanism (+5), deletion request mechanism (+5) |
| **Cross-Border** | 15 | Third-party services geo-assessment (+5), CDN/hosting location disclosure (+5), adequacy decision coverage (+5) |

```
gdpr_score = lawful_basis + privacy_policy + data_protection + rights + cross_border
```

---

### 4.4 PCI DSS Scoring (0–100)

For SMBs, Cerberus focuses on **SAQ A and SAQ A-EP** level requirements (most common for businesses that accept payments but don't store card data).

| Requirement Group | Max Points | Automated Checks |
|-------------------|-----------|------------------|
| **Network Security** (Req 1-2) | 20 | Firewall presence, unnecessary services, default credentials, network segmentation indicators |
| **Cardholder Data** (Req 3-4) | 25 | No card data in URLs/logs, encryption in transit (TLS 1.2+), payment page isolation |
| **Vulnerability Management** (Req 5-6) | 20 | Known CVEs on payment-facing systems, patch currency, secure development indicators |
| **Access Control** (Req 7-9) | 20 | Admin access restrictions, MFA on payment systems, unique user IDs |
| **Monitoring & Testing** (Req 10-12) | 15 | Logging on payment systems, security testing evidence, incident response plan indicators |

```
pci_score = network + cardholder + vuln_mgmt + access + monitoring
```

**Important:** Cerberus PCI scoring is a **readiness indicator**, not a replacement for a Qualified Security Assessor (QSA) or Self-Assessment Questionnaire (SAQ).

---

### 4.5 ISO 27001 Gap Analysis (0–100)

ISO 27001:2022 has 93 controls in Annex A, grouped into 4 themes. Cerberus maps automated findings to applicable controls:

| Theme | Controls | Automatable | Max Points |
|-------|----------|------------|-----------|
| **Organizational** (5.1–5.37) | 37 | ~15% | 25 |
| **People** (6.1–6.8) | 8 | ~10% | 15 |
| **Physical** (7.1–7.14) | 14 | ~5% | 10 |
| **Technological** (8.1–8.34) | 34 | ~50% | 50 |

**Scoring approach:**
- Each automatable control is checked: Pass = full points, Partial = half, Fail = 0
- Non-automatable controls contribute via the dashboard questionnaire
- Default assumption for unattested controls: **not implemented** (conservative)

```
iso_score = (tech_score / 50 × 50) + (org_score / 25 × 25) + 
            (people_score / 15 × 15) + (physical_score / 10 × 10)
```

**Gap analysis output includes:**
- List of implemented controls (evidence-backed)
- List of missing controls (prioritized by risk)
- Recommended implementation order (quick wins first)
- Estimated effort per control (hours)

---

## 5. Monitoring Scoring (15% of total)

| Check | Max Points | Scoring Logic |
|-------|-----------|---------------|
| **Uptime Monitoring** | 30 | Active monitoring configured: +15. Uptime > 99.9%: +15, > 99.5%: +10, > 99%: +5 |
| **SSL Certificate Health** | 25 | Expiry > 60 days: 25. 30–60 days: 20. 14–30 days: 10. < 14 days: 0 (critical alert). |
| **CVE Exposure** | 25 | No known CVEs on detected software: 25. Low-severity only: 15. Medium: 8. High/Critical: 0. |
| **Breach Monitoring** | 20 | Active monitoring: +10. No breaches found: +10. Breaches found with resolved status: +5. Unresolved breaches: 0. |

---

## 6. Human Factor Scoring (10% of total)

| Check | Max Points | Scoring Logic |
|-------|-----------|---------------|
| **Email Exposure** | 40 | Scored by number of employee emails found in public breach databases. 0 breached: 40. 1–2: 25. 3–5: 15. 6+: 0. |
| **Security Awareness** | 30 | Phishing simulation results (if integrated): pass rate × 30. No simulation: 15 (neutral). |
| **Credential Hygiene** | 30 | No credentials in paste sites: 30. Credentials found but passwords changed: 15. Active leaked credentials: 0. |

---

## 7. Score Interpretation

### For Business Owners

| Score | What It Means | Business Risk |
|-------|---------------|---------------|
| 90–100 🟢 | **Excellent.** You're ahead of 95% of businesses your size. | Minimal — maintain posture |
| 75–89 🟢 | **Good.** Strong security foundation with minor gaps. | Low — address findings at normal pace |
| 60–74 🟡 | **Fair.** This is where most SMBs land. Gaps exist but are fixable. | Moderate — prioritize top findings |
| 40–59 🟠 | **Needs Work.** Meaningful exposure that attackers could exploit. | High — create remediation plan |
| 0–39 🔴 | **Critical.** Significant vulnerabilities present. | Very High — immediate action needed |

### For MSPs / Security Consultants

The scoring breakdown provides:
- **Per-dimension drill-down** for targeted remediation
- **Per-framework compliance gaps** for regulatory planning
- **Trend tracking** over time (are clients improving?)
- **Client comparison** across your portfolio (anonymized benchmarking)

---

## 8. Score Freshness and Recalculation

- **Full rescan:** Configurable interval (default: weekly)
- **Incremental updates:** Monitoring checks update relevant sub-scores in real-time
- **Score staleness:** If no scan has run in > 14 days, the score displays a ⚠️ stale indicator
- **Manual trigger:** Operators can trigger a full rescan via API or dashboard

---

## 9. Methodology Transparency

Cerberus is **open-source** and the scoring logic is fully auditable in `core/scoring/`. Key files:

| File | Purpose |
|------|---------|
| `core/scoring/infrastructure.py` | Infrastructure dimension calculator |
| `core/scoring/authentication.py` | Authentication dimension calculator |
| `core/scoring/compliance/owasp.py` | OWASP Top 10 assessment |
| `core/scoring/compliance/soc2.py` | SOC 2 readiness calculator |
| `core/scoring/compliance/gdpr.py` | GDPR exposure assessment |
| `core/scoring/compliance/pci.py` | PCI DSS readiness calculator |
| `core/scoring/compliance/iso27001.py` | ISO 27001 gap analysis |
| `core/scoring/monitoring.py` | Monitoring dimension calculator |
| `core/scoring/human_factor.py` | Human factor dimension calculator |
| `core/scoring/composite.py` | Weighted composite calculator |

Every scoring decision includes a `rationale` field in the API response explaining why points were awarded or deducted.

---

## 10. Customization

### Per-Client Weight Adjustment

MSPs can adjust dimension weights per client based on their industry and risk profile:

```python
# Example: E-commerce client (payments matter more)
client_weights = {
    "infrastructure": 0.25,
    "authentication": 0.25,
    "compliance": 0.30,  # PCI DSS weight increased
    "monitoring": 0.15,
    "human_factor": 0.05
}
```

### Custom Compliance Frameworks

Organizations can define custom framework mappings in `config/custom_frameworks.yaml`:

```yaml
hipaa_readiness:
  name: "HIPAA Readiness"
  weight: 0.8
  controls:
    - id: "hipaa-164.312-a"
      name: "Access Control"
      maps_to: ["auth.mfa", "auth.password_policy", "auth.session"]
    - id: "hipaa-164.312-e"
      name: "Transmission Security"
      maps_to: ["infra.ssl_grade", "infra.http_headers"]
```

---

*This methodology is versioned alongside the Cerberus codebase. Current version: v1.0.*
