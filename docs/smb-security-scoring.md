# Cerberus SMB Security Scoring Methodology

## Overview

Cerberus scores Small & Medium Business security posture across 5 compliance frameworks on a 0–100 scale. Each framework score combines automated checks, configuration assessment, and policy evaluation.

## Scoring Frameworks

### 1. OWASP Top 10 (Web Application Security)
| Check | Weight | Method |
|-------|--------|--------|
| SQL Injection | 15% | Automated scanner + header analysis |
| Broken Authentication | 15% | Login endpoint assessment, MFA check |
| Sensitive Data Exposure | 10% | SSL/TLS grading, HSTS, cookie flags |
| XML External Entities | 5% | Content-type analysis |
| Broken Access Control | 15% | Authorization header testing |
| Security Misconfiguration | 15% | HTTP headers, server banners, directory listing |
| XSS | 10% | Reflected/stored XSS probe |
| Insecure Deserialization | 5% | Content-type and framework detection |
| Known Vulnerabilities | 5% | CVE matching against detected versions |
| Insufficient Logging | 5% | Security headers presence |

### 2. SOC 2 Type II Readiness
| Category | Weight | Checks |
|----------|--------|--------|
| Security (CC6) | 30% | Firewall, encryption, access controls, MFA |
| Availability (A1) | 20% | Uptime monitoring, backup verification, DR plan |
| Processing Integrity (PI1) | 15% | Data validation, error handling |
| Confidentiality (C1) | 20% | Encryption at rest/transit, data classification |
| Privacy (P1) | 15% | Cookie consent, privacy policy, data retention |

### 3. GDPR Exposure
| Area | Weight | Assessment |
|------|--------|------------|
| Data Collection Consent | 25% | Cookie banners, consent mechanisms |
| Data Subject Rights | 20% | Right to access/delete endpoints |
| Data Processing Records | 20% | Privacy policy completeness |
| Cross-Border Transfer | 15% | Server location, CDN geography |
| Breach Notification | 10% | Incident response contact availability |
| DPO Designation | 10% | Public DPO contact information |

### 4. PCI DSS (Payment Card Security)
| Requirement | Weight | Check |
|-------------|--------|-------|
| Firewall Configuration | 15% | Port scan, service exposure |
| Default Passwords | 10% | Common credential testing |
| Stored Cardholder Data | 15% | Payment page encryption analysis |
| Encrypted Transmission | 20% | TLS version, cipher strength |
| Anti-Virus | 10% | Malware detection headers |
| Secure Systems | 15% | Patch level, known CVEs |
| Access Control | 15% | Authentication mechanisms |

### 5. ISO 27001 Gap Analysis
| Domain | Weight | Assessment |
|--------|--------|------------|
| Information Security Policies | 10% | Security.txt, published policies |
| Asset Management | 15% | Domain/subdomain inventory accuracy |
| Access Control | 20% | Authentication, authorization, MFA |
| Cryptography | 15% | TLS config, certificate management |
| Operations Security | 15% | Logging, monitoring, vulnerability management |
| Communications Security | 15% | Network segmentation, email security (SPF/DKIM/DMARC) |
| Compliance | 10% | Regulatory alignment indicators |

## Score Calculation

```
Framework Score = Σ (check_score × weight) / Σ weights × 100

Overall Security Score = (OWASP × 0.25) + (SOC2 × 0.20) + (GDPR × 0.20) + (PCI × 0.20) + (ISO × 0.15)
```

## Score Interpretation

| Score | Rating | Recommendation |
|-------|--------|----------------|
| 90–100 | Excellent | Maintain current posture, minor improvements |
| 75–89 | Good | Address medium-risk findings within 30 days |
| 60–74 | Needs Improvement | Prioritize remediation of high-risk items |
| 40–59 | Poor | Immediate action required on critical findings |
| 0–39 | Critical | Engage security consultant, potential compliance violations |
