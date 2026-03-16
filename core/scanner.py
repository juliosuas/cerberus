"""Infrastructure scanner — port scans, SSL/TLS, headers, DNS, email security, and more."""

import socket
import ssl
import json
import datetime
import re
import subprocess
from urllib.parse import urlparse

import requests
import dns.resolver
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class InfrastructureScanner:
    """Comprehensive infrastructure security scanner for a target domain."""

    def __init__(self, target: str):
        self.target = self._normalize_target(target)
        self.domain = urlparse(f"https://{self.target}").hostname or self.target
        self.findings = []

    @staticmethod
    def _normalize_target(target: str) -> str:
        target = target.strip().lower()
        for prefix in ("https://", "http://"):
            if target.startswith(prefix):
                target = target[len(prefix):]
        return target.rstrip("/")

    def run_all(self) -> dict:
        """Run all scanner checks and return results."""
        results = {
            "target": self.target,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "checks": {},
            "findings": [],
        }

        checks = [
            ("port_scan", self.scan_ports),
            ("ssl_tls", self.check_ssl_tls),
            ("http_headers", self.check_http_headers),
            ("dns", self.check_dns),
            ("email_security", self.check_email_security),
            ("open_redirect", self.check_open_redirect),
            ("subdomain_takeover", self.check_subdomain_takeover),
        ]

        for name, check_fn in checks:
            try:
                results["checks"][name] = check_fn()
            except Exception as e:
                results["checks"][name] = {"status": "error", "error": str(e)}

        results["findings"] = self.findings
        return results

    def scan_ports(self) -> dict:
        """Scan common ports on the target."""
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
            27017: "MongoDB",
        }
        open_ports = []
        risky_ports = {21, 23, 445, 3306, 3389, 6379, 27017, 5432}

        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.domain, port))
                if result == 0:
                    open_ports.append({"port": port, "service": service})
                    if port in risky_ports:
                        self.findings.append({
                            "severity": "high" if port in {23, 445, 3389} else "medium",
                            "category": "port_scan",
                            "title": f"Risky port open: {port} ({service})",
                            "description": f"Port {port} ({service}) is publicly accessible. "
                                           f"This service should not be exposed to the internet.",
                            "remediation": f"Restrict access to port {port} using firewall rules. "
                                           f"Consider using a VPN for remote access.",
                        })
                sock.close()
            except (socket.timeout, OSError):
                continue

        return {"open_ports": open_ports, "total_scanned": len(common_ports)}

    def check_ssl_tls(self) -> dict:
        """Check SSL/TLS certificate and configuration."""
        result = {"grade": "F", "issues": []}
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(5)
                s.connect((self.domain, 443))
                cert_bin = s.getpeercert(binary_form=True)
                cert_info = s.getpeercert()
                protocol = s.version()

            cert = x509.load_der_x509_certificate(cert_bin, default_backend())

            # Check expiry
            days_left = (cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)).days
            result["expires_in_days"] = days_left
            result["issuer"] = cert_info.get("issuer", [{}])
            result["subject"] = cert_info.get("subject", [{}])
            result["protocol"] = protocol

            if days_left < 0:
                result["grade"] = "F"
                self.findings.append({
                    "severity": "critical",
                    "category": "ssl_tls",
                    "title": "SSL certificate has expired",
                    "description": f"Certificate expired {abs(days_left)} days ago.",
                    "remediation": "Renew the SSL certificate immediately.",
                })
            elif days_left < 30:
                result["grade"] = "B"
                self.findings.append({
                    "severity": "medium",
                    "category": "ssl_tls",
                    "title": "SSL certificate expiring soon",
                    "description": f"Certificate expires in {days_left} days.",
                    "remediation": "Renew the SSL certificate before expiry. Consider auto-renewal with Let's Encrypt.",
                })
            else:
                result["grade"] = "A"

            # Check protocol version
            weak_protocols = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
            if protocol in weak_protocols:
                result["grade"] = "C"
                self.findings.append({
                    "severity": "high",
                    "category": "ssl_tls",
                    "title": f"Weak TLS protocol: {protocol}",
                    "description": f"Server supports {protocol} which is deprecated and insecure.",
                    "remediation": "Disable TLS 1.0 and 1.1. Use TLS 1.2+ only.",
                })

        except ssl.SSLError as e:
            result["grade"] = "F"
            result["issues"].append(str(e))
            self.findings.append({
                "severity": "critical",
                "category": "ssl_tls",
                "title": "SSL/TLS configuration error",
                "description": f"SSL connection failed: {e}",
                "remediation": "Review and fix SSL/TLS configuration.",
            })
        except (socket.timeout, OSError) as e:
            result["grade"] = "F"
            result["issues"].append(f"Connection failed: {e}")

        return result

    def check_http_headers(self) -> dict:
        """Audit HTTP security headers."""
        required_headers = {
            "Strict-Transport-Security": {
                "severity": "high",
                "description": "HSTS not set. Browsers may connect over HTTP.",
                "remediation": "Add Strict-Transport-Security header with max-age of at least 31536000.",
            },
            "Content-Security-Policy": {
                "severity": "medium",
                "description": "No CSP header. Site is vulnerable to XSS and injection attacks.",
                "remediation": "Implement a Content-Security-Policy header.",
            },
            "X-Content-Type-Options": {
                "severity": "medium",
                "description": "Missing X-Content-Type-Options. Browsers may MIME-sniff responses.",
                "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
            },
            "X-Frame-Options": {
                "severity": "medium",
                "description": "No X-Frame-Options. Site may be vulnerable to clickjacking.",
                "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
            },
            "X-XSS-Protection": {
                "severity": "low",
                "description": "X-XSS-Protection header not set.",
                "remediation": "Add 'X-XSS-Protection: 1; mode=block' header.",
            },
            "Referrer-Policy": {
                "severity": "low",
                "description": "No Referrer-Policy header. Referrer may leak sensitive URLs.",
                "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
            },
            "Permissions-Policy": {
                "severity": "low",
                "description": "No Permissions-Policy header.",
                "remediation": "Add Permissions-Policy header to control browser features.",
            },
        }

        result = {"present": [], "missing": [], "score": 0}
        try:
            resp = requests.get(f"https://{self.domain}", timeout=10, allow_redirects=True)
            headers = resp.headers

            for header, info in required_headers.items():
                if header.lower() in {k.lower() for k in headers.keys()}:
                    result["present"].append(header)
                else:
                    result["missing"].append(header)
                    self.findings.append({
                        "severity": info["severity"],
                        "category": "http_headers",
                        "title": f"Missing header: {header}",
                        "description": info["description"],
                        "remediation": info["remediation"],
                    })

            # Check for server info leakage
            if "Server" in headers:
                server_val = headers["Server"]
                if any(v in server_val.lower() for v in ["apache/", "nginx/", "iis/"]):
                    self.findings.append({
                        "severity": "low",
                        "category": "http_headers",
                        "title": "Server version disclosed",
                        "description": f"Server header reveals: {server_val}",
                        "remediation": "Remove version information from the Server header.",
                    })

            total = len(required_headers)
            present = len(result["present"])
            result["score"] = round((present / total) * 100) if total else 0

        except requests.RequestException as e:
            result["error"] = str(e)

        return result

    def check_dns(self) -> dict:
        """Check DNS configuration for security issues."""
        result = {"records": {}, "issues": []}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        # Check various record types
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CAA"]:
            try:
                answers = resolver.resolve(self.domain, rtype)
                result["records"][rtype] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, Exception):
                result["records"][rtype] = []

        # Check for DNSSEC
        try:
            answers = resolver.resolve(self.domain, "DNSKEY")
            result["dnssec"] = True
        except Exception:
            result["dnssec"] = False
            self.findings.append({
                "severity": "medium",
                "category": "dns",
                "title": "DNSSEC not enabled",
                "description": "Domain does not have DNSSEC configured.",
                "remediation": "Enable DNSSEC with your DNS provider to prevent DNS spoofing.",
            })

        # Check for CAA records
        if not result["records"].get("CAA"):
            self.findings.append({
                "severity": "low",
                "category": "dns",
                "title": "No CAA records",
                "description": "No Certificate Authority Authorization records found.",
                "remediation": "Add CAA records to restrict which CAs can issue certificates for your domain.",
            })

        return result

    def check_email_security(self) -> dict:
        """Check SPF, DKIM, and DMARC records."""
        result = {"spf": None, "dmarc": None, "dkim": None}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        # SPF
        try:
            answers = resolver.resolve(self.domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=spf1"):
                    result["spf"] = txt
                    if "+all" in txt:
                        self.findings.append({
                            "severity": "high",
                            "category": "email_security",
                            "title": "SPF record uses +all",
                            "description": "SPF record allows any server to send email for this domain.",
                            "remediation": "Change +all to ~all or -all in the SPF record.",
                        })
                    break
        except Exception:
            pass

        if not result["spf"]:
            self.findings.append({
                "severity": "high",
                "category": "email_security",
                "title": "No SPF record",
                "description": "Domain has no SPF record. Anyone can spoof emails from this domain.",
                "remediation": "Add an SPF TXT record to specify authorized mail servers.",
            })

        # DMARC
        try:
            answers = resolver.resolve(f"_dmarc.{self.domain}", "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=DMARC1"):
                    result["dmarc"] = txt
                    if "p=none" in txt:
                        self.findings.append({
                            "severity": "medium",
                            "category": "email_security",
                            "title": "DMARC policy set to none",
                            "description": "DMARC is in monitor-only mode and won't reject spoofed emails.",
                            "remediation": "Change DMARC policy to 'quarantine' or 'reject'.",
                        })
                    break
        except Exception:
            pass

        if not result["dmarc"]:
            self.findings.append({
                "severity": "high",
                "category": "email_security",
                "title": "No DMARC record",
                "description": "Domain has no DMARC record. Email spoofing is not prevented.",
                "remediation": "Add a DMARC TXT record at _dmarc.yourdomain.com.",
            })

        # DKIM — check common selectors
        for selector in ["default", "google", "selector1", "selector2", "k1"]:
            try:
                answers = resolver.resolve(f"{selector}._domainkey.{self.domain}", "TXT")
                result["dkim"] = f"{selector}._domainkey"
                break
            except Exception:
                continue

        if not result["dkim"]:
            self.findings.append({
                "severity": "medium",
                "category": "email_security",
                "title": "No DKIM record found",
                "description": "Could not find DKIM records for common selectors.",
                "remediation": "Configure DKIM signing for outbound email.",
            })

        return result

    def check_open_redirect(self) -> dict:
        """Check for open redirect vulnerabilities."""
        result = {"vulnerable": False, "tested_params": []}
        test_payloads = [
            "?next=https://evil.com",
            "?redirect=https://evil.com",
            "?url=https://evil.com",
            "?return=https://evil.com",
            "?goto=https://evil.com",
        ]

        for payload in test_payloads:
            try:
                resp = requests.get(
                    f"https://{self.domain}{payload}",
                    timeout=5,
                    allow_redirects=False,
                )
                result["tested_params"].append(payload.split("=")[0][1:])
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location:
                        result["vulnerable"] = True
                        self.findings.append({
                            "severity": "medium",
                            "category": "open_redirect",
                            "title": f"Open redirect via {payload.split('=')[0][1:]} parameter",
                            "description": "Server redirects to attacker-controlled URL.",
                            "remediation": "Validate redirect URLs against a whitelist of allowed domains.",
                        })
            except requests.RequestException:
                continue

        return result

    def check_subdomain_takeover(self) -> dict:
        """Check for potential subdomain takeover vulnerabilities."""
        result = {"checked": [], "vulnerable": []}
        # Common subdomain prefixes to check
        prefixes = ["www", "mail", "blog", "shop", "app", "dev", "staging", "api", "cdn", "test"]
        takeover_fingerprints = [
            "There isn't a GitHub Pages site here",
            "NoSuchBucket",
            "No such app",
            "is not a registered InCloud",
            "no-such-app",
            "Domain is not configured",
        ]

        for prefix in prefixes:
            subdomain = f"{prefix}.{self.domain}"
            try:
                dns.resolver.resolve(subdomain, "CNAME")
                try:
                    resp = requests.get(f"https://{subdomain}", timeout=5)
                    body = resp.text[:2000]
                    for fingerprint in takeover_fingerprints:
                        if fingerprint in body:
                            result["vulnerable"].append(subdomain)
                            self.findings.append({
                                "severity": "high",
                                "category": "subdomain_takeover",
                                "title": f"Potential subdomain takeover: {subdomain}",
                                "description": f"Subdomain {subdomain} has a dangling CNAME and may be vulnerable to takeover.",
                                "remediation": f"Remove the CNAME record for {subdomain} or claim the resource.",
                            })
                            break
                except requests.RequestException:
                    pass
                result["checked"].append(subdomain)
            except Exception:
                continue

        return result
