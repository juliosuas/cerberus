"""Seed Cerberus with demo data for Acme Corp — makes the dashboard look impressive."""

import json
import sys
import os

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.db import (
    init_db, create_target, create_scan, update_scan,
    create_finding, save_compliance_score, create_breach,
)


def seed():
    """Populate the database with realistic Acme Corp demo data."""
    print("[*] Initializing database...")
    init_db()

    # ------------------------------------------------------------------
    # 3 Targets
    # ------------------------------------------------------------------
    targets = [
        {"name": "Acme Corp Main Site", "domain": "acmecorp.com",
         "emails": ["admin@acmecorp.com", "security@acmecorp.com"], "tags": ["production", "public"]},
        {"name": "Acme Corp API", "domain": "api.acmecorp.com",
         "emails": ["devops@acmecorp.com"], "tags": ["production", "api"]},
        {"name": "Acme Corp Mail Server", "domain": "mail.acmecorp.com",
         "emails": ["it@acmecorp.com"], "tags": ["production", "email"]},
    ]

    target_ids = {}
    for t in targets:
        tid = create_target(t["name"], t["domain"], emails=t["emails"], tags=t["tags"])
        target_ids[t["domain"]] = tid
        print(f"  [+] Target: {t['name']} (id={tid})")

    # ------------------------------------------------------------------
    # Scans (one completed scan per target)
    # ------------------------------------------------------------------
    scan_ids = {}
    for domain, tid in target_ids.items():
        sid = create_scan(tid, "full")
        scan_results = {
            "target": domain,
            "checks": {
                "port_scan": {"open_ports": [{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}]},
                "ssl_tls": {"grade": "B" if domain == "acmecorp.com" else "A", "expires_in_days": 45},
                "http_headers": {"score": 43, "present": ["X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection"],
                                 "missing": ["Strict-Transport-Security", "Content-Security-Policy", "Referrer-Policy", "Permissions-Policy"]},
                "dns": {"dnssec": False},
                "email_security": {"spf": "v=spf1 include:_spf.google.com ~all", "dmarc": None, "dkim": None},
            },
        }
        update_scan(sid, "completed", scan_results)
        scan_ids[domain] = sid
        print(f"  [+] Scan completed: {domain} (id={sid})")

    # ------------------------------------------------------------------
    # 15 Findings (mix of Critical / High / Medium / Low)
    # ------------------------------------------------------------------
    main_id = target_ids["acmecorp.com"]
    api_id = target_ids["api.acmecorp.com"]
    mail_id = target_ids["mail.acmecorp.com"]
    main_scan = scan_ids["acmecorp.com"]
    api_scan = scan_ids["api.acmecorp.com"]
    mail_scan = scan_ids["mail.acmecorp.com"]

    findings_data = [
        # --- Critical (2) ---
        {"scan_id": main_scan, "target_id": main_id, "severity": "critical", "category": "ssl_tls",
         "title": "SSL certificate expiring in 5 days",
         "description": "The primary SSL certificate for acmecorp.com expires in 5 days. If not renewed, visitors will see browser security warnings.",
         "remediation": "Renew the SSL certificate immediately. Enable auto-renewal with Let's Encrypt or your CA."},
        {"scan_id": api_scan, "target_id": api_id, "severity": "critical", "category": "port_scan",
         "title": "MongoDB port 27017 publicly accessible",
         "description": "The MongoDB default port is open and accessible from the internet on api.acmecorp.com. This exposes the database to unauthorized access.",
         "remediation": "Restrict port 27017 via firewall rules. Bind MongoDB to 127.0.0.1 and use SSH tunnels for remote access."},

        # --- High (4) ---
        {"scan_id": main_scan, "target_id": main_id, "severity": "high", "category": "http_headers",
         "title": "Missing header: Strict-Transport-Security",
         "description": "HSTS not set. Browsers may connect over insecure HTTP, enabling man-in-the-middle attacks.",
         "remediation": "Add Strict-Transport-Security header with max-age of at least 31536000."},
        {"scan_id": main_scan, "target_id": main_id, "severity": "high", "category": "email_security",
         "title": "No DMARC record",
         "description": "Domain has no DMARC record. Attackers can spoof emails from acmecorp.com to target employees and customers.",
         "remediation": "Add a DMARC TXT record at _dmarc.acmecorp.com. Start with p=none for monitoring, then move to p=reject."},
        {"scan_id": api_scan, "target_id": api_id, "severity": "high", "category": "port_scan",
         "title": "Risky port open: 3389 (RDP)",
         "description": "Remote Desktop Protocol is publicly accessible. This is a common target for brute-force attacks.",
         "remediation": "Disable public RDP. Use a VPN or bastion host for remote management."},
        {"scan_id": mail_scan, "target_id": mail_id, "severity": "high", "category": "email_security",
         "title": "SPF record uses +all",
         "description": "The SPF record allows any server to send email as mail.acmecorp.com. This effectively disables SPF protection.",
         "remediation": "Change +all to -all in the SPF record to reject unauthorized senders."},

        # --- Medium (5) ---
        {"scan_id": main_scan, "target_id": main_id, "severity": "medium", "category": "http_headers",
         "title": "Missing header: Content-Security-Policy",
         "description": "No CSP header. The site is vulnerable to cross-site scripting (XSS) and code injection attacks.",
         "remediation": "Implement a Content-Security-Policy header. Start with report-only mode to identify issues."},
        {"scan_id": main_scan, "target_id": main_id, "severity": "medium", "category": "dns",
         "title": "DNSSEC not enabled",
         "description": "Domain does not have DNSSEC configured. DNS responses can be spoofed.",
         "remediation": "Enable DNSSEC with your DNS provider to prevent DNS cache poisoning."},
        {"scan_id": api_scan, "target_id": api_id, "severity": "medium", "category": "port_scan",
         "title": "Risky port open: 6379 (Redis)",
         "description": "Redis is accessible from the internet. Default Redis has no authentication.",
         "remediation": "Restrict port 6379 via firewall. Enable Redis AUTH and bind to localhost."},
        {"scan_id": mail_scan, "target_id": mail_id, "severity": "medium", "category": "email_security",
         "title": "No DKIM record found",
         "description": "Could not find DKIM records for common selectors. Email authenticity cannot be verified.",
         "remediation": "Configure DKIM signing for outbound email with your email provider."},
        {"scan_id": mail_scan, "target_id": mail_id, "severity": "medium", "category": "email_security",
         "title": "DMARC policy set to none",
         "description": "DMARC is in monitor-only mode and will not reject spoofed emails.",
         "remediation": "Upgrade DMARC policy from p=none to p=quarantine or p=reject after monitoring."},

        # --- Low (4) ---
        {"scan_id": main_scan, "target_id": main_id, "severity": "low", "category": "http_headers",
         "title": "Missing header: Referrer-Policy",
         "description": "No Referrer-Policy header. Full URLs including query strings may leak to third parties.",
         "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header."},
        {"scan_id": main_scan, "target_id": main_id, "severity": "low", "category": "http_headers",
         "title": "Missing header: Permissions-Policy",
         "description": "No Permissions-Policy header. Browser features like camera and microphone are unrestricted.",
         "remediation": "Add Permissions-Policy header to disable unnecessary browser APIs."},
        {"scan_id": main_scan, "target_id": main_id, "severity": "low", "category": "http_headers",
         "title": "Server version disclosed",
         "description": "Server header reveals: nginx/1.21.6. Version information helps attackers find known exploits.",
         "remediation": "Remove version information from the Server header in nginx config."},
        {"scan_id": api_scan, "target_id": api_id, "severity": "low", "category": "dns",
         "title": "No CAA records",
         "description": "No Certificate Authority Authorization records found. Any CA can issue certificates for this domain.",
         "remediation": "Add CAA records to restrict certificate issuance to your preferred CA."},
    ]

    for f in findings_data:
        fid = create_finding(**f)
        print(f"  [+] Finding [{f['severity'].upper():>8}]: {f['title'][:60]}")

    # ------------------------------------------------------------------
    # Compliance Scores (per the spec: OWASP 72, SOC2 65, GDPR 80, PCI 58)
    # ------------------------------------------------------------------
    compliance_scores = [
        # acmecorp.com
        {"target_id": main_id, "scan_id": main_scan, "framework": "owasp_top_10", "score": 72, "grade": "C",
         "details": {"checks_passed": 6, "checks_failed": 2, "checks_warn": 2}},
        {"target_id": main_id, "scan_id": main_scan, "framework": "soc2", "score": 65, "grade": "D",
         "details": {"controls_passed": 2, "controls_failed": 1, "controls_warn": 2}},
        {"target_id": main_id, "scan_id": main_scan, "framework": "gdpr", "score": 80, "grade": "B",
         "details": {"checks_passed": 3, "checks_failed": 1, "checks_warn": 1}},
        {"target_id": main_id, "scan_id": main_scan, "framework": "pci_dss", "score": 58, "grade": "F",
         "details": {"requirements_passed": 2, "requirements_failed": 2, "requirements_warn": 2}},
        {"target_id": main_id, "scan_id": main_scan, "framework": "iso_27001", "score": 70, "grade": "C",
         "details": {"controls_passed": 2, "controls_failed": 2, "controls_warn": 2}},
        # api.acmecorp.com
        {"target_id": api_id, "scan_id": api_scan, "framework": "owasp_top_10", "score": 68, "grade": "D",
         "details": {"checks_passed": 5, "checks_failed": 3, "checks_warn": 2}},
        {"target_id": api_id, "scan_id": api_scan, "framework": "soc2", "score": 60, "grade": "D",
         "details": {"controls_passed": 1, "controls_failed": 2, "controls_warn": 2}},
        {"target_id": api_id, "scan_id": api_scan, "framework": "pci_dss", "score": 50, "grade": "F",
         "details": {"requirements_passed": 1, "requirements_failed": 3, "requirements_warn": 2}},
        # mail.acmecorp.com
        {"target_id": mail_id, "scan_id": mail_scan, "framework": "owasp_top_10", "score": 78, "grade": "C",
         "details": {"checks_passed": 7, "checks_failed": 1, "checks_warn": 2}},
        {"target_id": mail_id, "scan_id": mail_scan, "framework": "gdpr", "score": 75, "grade": "C",
         "details": {"checks_passed": 3, "checks_failed": 1, "checks_warn": 1}},
    ]

    for cs in compliance_scores:
        save_compliance_score(**cs)
        print(f"  [+] Compliance: {cs['framework']:>12} = {cs['score']}/100 ({cs['grade']}) for target {cs['target_id']}")

    # ------------------------------------------------------------------
    # 5 Breach Alerts
    # ------------------------------------------------------------------
    breaches_data = [
        {"target_id": main_id, "breach_type": "credential_leak", "severity": "critical",
         "title": "Employee credentials found on dark web marketplace",
         "description": "3 employee email/password combinations for acmecorp.com were found on a dark web marketplace (BreachForums). Accounts: admin@, hr@, finance@acmecorp.com.",
         "source": "Dark Web Monitor"},
        {"target_id": main_id, "breach_type": "data_breach", "severity": "high",
         "title": "Company data in third-party breach (CloudVendor Inc.)",
         "description": "Acme Corp customer records were exposed in the CloudVendor Inc. breach (Jan 2026). Approximately 12,000 customer email addresses affected.",
         "source": "Have I Been Pwned"},
        {"target_id": api_id, "breach_type": "credential_leak", "severity": "high",
         "title": "API keys exposed in public GitHub repository",
         "description": "Production API keys for api.acmecorp.com were found in a public GitHub repository (acme-dev/legacy-scripts). Keys appear active.",
         "source": "GitHub Exposure Monitor"},
        {"target_id": mail_id, "breach_type": "domain_mention", "severity": "medium",
         "title": "Domain mentioned in paste site dump",
         "description": "mail.acmecorp.com was referenced in a Pastebin dump containing a list of mail servers targeted for spam relay testing.",
         "source": "Paste Monitor"},
        {"target_id": main_id, "breach_type": "credential_leak", "severity": "medium",
         "title": "Credentials in historic LinkedIn breach",
         "description": "5 email addresses @acmecorp.com appeared in the 2024 LinkedIn data breach compilation. Passwords may be reused.",
         "source": "Have I Been Pwned"},
    ]

    for b in breaches_data:
        create_breach(**b)
        print(f"  [+] Breach [{b['severity'].upper():>8}]: {b['title'][:60]}")

    # ------------------------------------------------------------------
    print("\n[*] Seed complete!")
    print(f"    Targets:    {len(targets)}")
    print(f"    Findings:   {len(findings_data)} (2 Critical, 4 High, 5 Medium, 4 Low)")
    print(f"    Compliance: {len(compliance_scores)} scores across 5 frameworks")
    print(f"    Breaches:   {len(breaches_data)} alerts")
    print("\n    Dashboard should now look impressive for demos.")


if __name__ == "__main__":
    seed()
