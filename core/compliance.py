"""Compliance checker — OWASP Top 10, SOC 2, GDPR, PCI DSS, ISO 27001."""

import datetime
import requests


class ComplianceChecker:
    """Run compliance checks against a target and produce 0-100 scores with recommendations."""

    def __init__(self, target: str, scan_results: dict = None):
        self.target = target.strip().lower()
        for prefix in ("https://", "http://"):
            if self.target.startswith(prefix):
                self.target = self.target[len(prefix):]
        self.scan_results = scan_results or {}
        self.findings = self.scan_results.get("findings", [])

    def run_all(self) -> dict:
        return {
            "target": self.target,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "frameworks": {
                "owasp_top_10": self.check_owasp_top_10(),
                "soc2": self.check_soc2(),
                "gdpr": self.check_gdpr(),
                "pci_dss": self.check_pci_dss(),
                "iso_27001": self.check_iso_27001(),
            },
        }

    def check_owasp_top_10(self) -> dict:
        """OWASP Top 10 web application security check."""
        score = 100
        recommendations = []
        checks = []

        # A01: Broken Access Control
        check = {"id": "A01", "name": "Broken Access Control", "status": "pass"}
        try:
            resp = requests.get(f"https://{self.target}/.env", timeout=5)
            if resp.status_code == 200:
                check["status"] = "fail"
                score -= 15
                recommendations.append("Sensitive file (.env) is publicly accessible. Restrict access immediately.")
        except requests.RequestException:
            pass
        checks.append(check)

        # A02: Cryptographic Failures
        check = {"id": "A02", "name": "Cryptographic Failures", "status": "pass"}
        ssl_findings = [f for f in self.findings if f.get("category") == "ssl_tls"]
        if ssl_findings:
            check["status"] = "fail"
            score -= 15
            recommendations.append("Fix SSL/TLS issues: " + "; ".join(f["title"] for f in ssl_findings))
        checks.append(check)

        # A03: Injection
        check = {"id": "A03", "name": "Injection", "status": "pass"}
        csp_missing = any(f.get("title", "").startswith("Missing header: Content-Security-Policy") for f in self.findings)
        if csp_missing:
            check["status"] = "warn"
            score -= 5
            recommendations.append("Implement Content-Security-Policy to mitigate injection attacks.")
        checks.append(check)

        # A04: Insecure Design — informational
        checks.append({"id": "A04", "name": "Insecure Design", "status": "info",
                        "note": "Requires manual review of application architecture."})

        # A05: Security Misconfiguration
        check = {"id": "A05", "name": "Security Misconfiguration", "status": "pass"}
        header_findings = [f for f in self.findings if f.get("category") == "http_headers"]
        if len(header_findings) > 3:
            check["status"] = "fail"
            score -= 15
            recommendations.append(f"{len(header_findings)} security headers are missing. Fix header configuration.")
        elif header_findings:
            check["status"] = "warn"
            score -= 5
            recommendations.append("Some security headers are missing.")
        checks.append(check)

        # A06: Vulnerable Components
        check = {"id": "A06", "name": "Vulnerable Components", "status": "pass"}
        server_disclosed = any("Server version disclosed" in f.get("title", "") for f in self.findings)
        if server_disclosed:
            check["status"] = "warn"
            score -= 5
            recommendations.append("Server version is disclosed. Remove version info from headers.")
        checks.append(check)

        # A07: Auth Failures — needs manual testing
        checks.append({"id": "A07", "name": "Identification & Auth Failures", "status": "info",
                        "note": "Requires manual authentication testing."})

        # A08: Software & Data Integrity
        check = {"id": "A08", "name": "Software & Data Integrity", "status": "pass"}
        try:
            resp = requests.get(f"https://{self.target}", timeout=10)
            if "integrity=" not in resp.text and "<script src=" in resp.text:
                check["status"] = "warn"
                score -= 5
                recommendations.append("External scripts lack Subresource Integrity (SRI) attributes.")
        except requests.RequestException:
            pass
        checks.append(check)

        # A09: Logging & Monitoring — informational
        checks.append({"id": "A09", "name": "Security Logging & Monitoring", "status": "info",
                        "note": "Requires internal infrastructure review."})

        # A10: SSRF — informational
        checks.append({"id": "A10", "name": "Server-Side Request Forgery", "status": "info",
                        "note": "Requires manual testing of server-side request functionality."})

        return {
            "score": max(0, score),
            "grade": self._score_to_grade(max(0, score)),
            "checks": checks,
            "recommendations": recommendations,
        }

    def check_soc2(self) -> dict:
        """Basic SOC 2 readiness assessment based on external indicators."""
        score = 100
        recommendations = []
        controls = []

        # CC6.1: Logical and Physical Access Controls
        ctrl = {"id": "CC6.1", "name": "Logical Access Controls", "status": "pass"}
        risky_ports = [f for f in self.findings if f.get("category") == "port_scan" and f.get("severity") in ("high", "critical")]
        if risky_ports:
            ctrl["status"] = "fail"
            score -= 20
            recommendations.append("Close risky open ports. Implement network segmentation and access controls.")
        controls.append(ctrl)

        # CC6.6: Security for Transmitted Data
        ctrl = {"id": "CC6.6", "name": "Encryption in Transit", "status": "pass"}
        ssl_checks = self.scan_results.get("checks", {}).get("ssl_tls", {})
        ssl_grade = ssl_checks.get("grade", "F")
        if ssl_grade in ("D", "F"):
            ctrl["status"] = "fail"
            score -= 20
            recommendations.append("Fix SSL/TLS configuration to ensure data encryption in transit.")
        elif ssl_grade in ("B", "C"):
            ctrl["status"] = "warn"
            score -= 10
        controls.append(ctrl)

        # CC6.7: Data Integrity
        ctrl = {"id": "CC6.7", "name": "Data Integrity", "status": "pass"}
        hsts_missing = any("Strict-Transport-Security" in f.get("title", "") for f in self.findings)
        if hsts_missing:
            ctrl["status"] = "warn"
            score -= 10
            recommendations.append("Enable HSTS to prevent downgrade attacks.")
        controls.append(ctrl)

        # CC7.2: Monitoring
        ctrl = {"id": "CC7.2", "name": "Security Monitoring", "status": "info",
                "note": "Requires internal security monitoring review."}
        controls.append(ctrl)

        # CC8.1: Change Management
        controls.append({"id": "CC8.1", "name": "Change Management", "status": "info",
                          "note": "Requires review of internal change management processes."})

        return {
            "score": max(0, score),
            "grade": self._score_to_grade(max(0, score)),
            "controls": controls,
            "recommendations": recommendations,
        }

    def check_gdpr(self) -> dict:
        """GDPR data exposure check."""
        score = 100
        recommendations = []
        checks = []

        # Check for privacy policy
        check = {"id": "GDPR-1", "name": "Privacy Policy", "status": "pass"}
        try:
            for path in ["/privacy", "/privacy-policy", "/legal/privacy"]:
                resp = requests.get(f"https://{self.target}{path}", timeout=5)
                if resp.status_code == 200:
                    break
            else:
                check["status"] = "fail"
                score -= 20
                recommendations.append("No privacy policy page found. GDPR requires a clear privacy policy.")
        except requests.RequestException:
            check["status"] = "warn"
        checks.append(check)

        # Check for cookie consent
        check = {"id": "GDPR-2", "name": "Cookie Consent", "status": "pass"}
        try:
            resp = requests.get(f"https://{self.target}", timeout=10)
            body = resp.text.lower()
            cookie_terms = ["cookie consent", "cookie policy", "cookieconsent", "cookie-consent", "gdpr"]
            if not any(term in body for term in cookie_terms):
                check["status"] = "warn"
                score -= 10
                recommendations.append("No cookie consent mechanism detected. Consider implementing one.")
        except requests.RequestException:
            pass
        checks.append(check)

        # Check for data exposure via headers
        check = {"id": "GDPR-3", "name": "Data Exposure Headers", "status": "pass"}
        try:
            resp = requests.get(f"https://{self.target}", timeout=10)
            if "X-Powered-By" in resp.headers:
                check["status"] = "warn"
                score -= 5
                recommendations.append("Remove X-Powered-By header to reduce information exposure.")
        except requests.RequestException:
            pass
        checks.append(check)

        # Email security (data in transit)
        check = {"id": "GDPR-4", "name": "Email Data Protection", "status": "pass"}
        email_findings = [f for f in self.findings if f.get("category") == "email_security"]
        if email_findings:
            check["status"] = "fail"
            score -= 15
            recommendations.append("Fix email security (SPF/DKIM/DMARC) to protect personal data in transit.")
        checks.append(check)

        # Encryption
        check = {"id": "GDPR-5", "name": "Encryption (Art. 32)", "status": "pass"}
        ssl_issues = [f for f in self.findings if f.get("category") == "ssl_tls" and f.get("severity") in ("critical", "high")]
        if ssl_issues:
            check["status"] = "fail"
            score -= 20
            recommendations.append("Fix critical SSL/TLS issues. GDPR Article 32 requires appropriate encryption.")
        checks.append(check)

        return {
            "score": max(0, score),
            "grade": self._score_to_grade(max(0, score)),
            "checks": checks,
            "recommendations": recommendations,
        }

    def check_pci_dss(self) -> dict:
        """PCI DSS basic requirements check."""
        score = 100
        recommendations = []
        requirements = []

        # Req 1: Install and maintain network security controls
        req = {"id": "1", "name": "Network Security Controls", "status": "pass"}
        risky = [f for f in self.findings if f.get("category") == "port_scan"]
        if risky:
            req["status"] = "fail"
            score -= 20
            recommendations.append("PCI Req 1: Restrict unnecessary open ports and services.")
        requirements.append(req)

        # Req 2: Secure configurations
        req = {"id": "2", "name": "Secure Configurations", "status": "pass"}
        header_issues = [f for f in self.findings if f.get("category") == "http_headers"]
        if len(header_issues) >= 3:
            req["status"] = "fail"
            score -= 15
            recommendations.append("PCI Req 2: Apply secure configuration to all system components.")
        requirements.append(req)

        # Req 4: Encrypt transmission of cardholder data
        req = {"id": "4", "name": "Encrypt Transmissions", "status": "pass"}
        ssl_grade = self.scan_results.get("checks", {}).get("ssl_tls", {}).get("grade", "F")
        if ssl_grade in ("D", "F"):
            req["status"] = "fail"
            score -= 20
            recommendations.append("PCI Req 4: Fix SSL/TLS to encrypt cardholder data in transit.")
        elif ssl_grade in ("B", "C"):
            req["status"] = "warn"
            score -= 10
        requirements.append(req)

        # Req 6: Develop and maintain secure systems
        req = {"id": "6", "name": "Secure Development", "status": "pass"}
        csp = any("Content-Security-Policy" in f.get("title", "") for f in self.findings)
        if csp:
            req["status"] = "warn"
            score -= 10
            recommendations.append("PCI Req 6: Implement CSP and other security headers.")
        requirements.append(req)

        # Req 11: Test security regularly
        requirements.append({"id": "11", "name": "Regular Security Testing", "status": "info",
                              "note": "Requires evidence of regular vulnerability scanning and penetration testing."})

        # Req 12: Information security policy
        requirements.append({"id": "12", "name": "Security Policy", "status": "info",
                              "note": "Requires review of organizational security policies."})

        return {
            "score": max(0, score),
            "grade": self._score_to_grade(max(0, score)),
            "requirements": requirements,
            "recommendations": recommendations,
        }

    def check_iso_27001(self) -> dict:
        """ISO 27001 basic gap analysis."""
        score = 100
        recommendations = []
        controls = []

        # A.8: Asset Management (observable via DNS/domain config)
        ctrl = {"id": "A.8", "name": "Asset Management", "status": "pass"}
        dns_checks = self.scan_results.get("checks", {}).get("dns", {})
        if not dns_checks.get("dnssec", False):
            ctrl["status"] = "warn"
            score -= 5
            recommendations.append("A.8: Enable DNSSEC for domain integrity.")
        controls.append(ctrl)

        # A.10: Cryptography
        ctrl = {"id": "A.10", "name": "Cryptography", "status": "pass"}
        ssl_grade = self.scan_results.get("checks", {}).get("ssl_tls", {}).get("grade", "F")
        if ssl_grade in ("D", "F"):
            ctrl["status"] = "fail"
            score -= 20
            recommendations.append("A.10: Cryptographic controls are inadequate. Fix SSL/TLS configuration.")
        elif ssl_grade in ("B", "C"):
            ctrl["status"] = "warn"
            score -= 10
        controls.append(ctrl)

        # A.13: Communications Security
        ctrl = {"id": "A.13", "name": "Communications Security", "status": "pass"}
        email_findings = [f for f in self.findings if f.get("category") == "email_security"]
        if email_findings:
            ctrl["status"] = "fail"
            score -= 15
            recommendations.append("A.13: Email security configuration is incomplete (SPF/DKIM/DMARC).")
        controls.append(ctrl)

        # A.14: System Acquisition, Development, Maintenance
        ctrl = {"id": "A.14", "name": "Secure Development", "status": "pass"}
        header_count = len([f for f in self.findings if f.get("category") == "http_headers"])
        if header_count > 3:
            ctrl["status"] = "fail"
            score -= 15
            recommendations.append("A.14: Application security headers are significantly deficient.")
        elif header_count > 0:
            ctrl["status"] = "warn"
            score -= 5
        controls.append(ctrl)

        # A.12: Operations Security
        controls.append({"id": "A.12", "name": "Operations Security", "status": "info",
                          "note": "Requires internal review of operational procedures."})

        # A.18: Compliance
        controls.append({"id": "A.18", "name": "Compliance", "status": "info",
                          "note": "Requires review of legal and regulatory requirements."})

        return {
            "score": max(0, score),
            "grade": self._score_to_grade(max(0, score)),
            "controls": controls,
            "recommendations": recommendations,
        }

    @staticmethod
    def _score_to_grade(score: int) -> str:
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        return "F"
