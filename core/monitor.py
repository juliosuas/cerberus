"""Continuous monitoring — uptime, SSL expiry, domain expiry, CVE matching, defacement detection."""

import datetime
import hashlib
import socket
import ssl

import requests
import whois
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class ContinuousMonitor:
    """Monitors targets for uptime, cert expiry, domain expiry, CVEs, and defacement."""

    def __init__(self, target: str):
        self.target = target.strip().lower().rstrip("/")
        for prefix in ("https://", "http://"):
            if self.target.startswith(prefix):
                self.target = self.target[len(prefix):]
        self.alerts = []

    def run_all(self) -> dict:
        results = {
            "target": self.target,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "checks": {},
            "alerts": [],
        }

        checks = [
            ("uptime", self.check_uptime),
            ("ssl_expiry", self.check_ssl_expiry),
            ("domain_expiry", self.check_domain_expiry),
            ("cve_match", self.check_cve_matching),
            ("defacement", self.check_defacement),
        ]

        for name, fn in checks:
            try:
                results["checks"][name] = fn()
            except Exception as e:
                results["checks"][name] = {"status": "error", "error": str(e)}

        results["alerts"] = self.alerts
        return results

    def check_uptime(self) -> dict:
        """Check if target is up and measure response time."""
        result = {"up": False, "response_time_ms": None, "status_code": None}
        try:
            resp = requests.get(f"https://{self.target}", timeout=15)
            result["up"] = True
            result["response_time_ms"] = round(resp.elapsed.total_seconds() * 1000)
            result["status_code"] = resp.status_code

            if resp.status_code >= 500:
                self.alerts.append({
                    "severity": "critical",
                    "type": "uptime",
                    "title": f"Server error: HTTP {resp.status_code}",
                    "message": f"{self.target} returned HTTP {resp.status_code}.",
                })
            elif result["response_time_ms"] > 5000:
                self.alerts.append({
                    "severity": "medium",
                    "type": "uptime",
                    "title": "Slow response time",
                    "message": f"{self.target} took {result['response_time_ms']}ms to respond.",
                })
        except requests.ConnectionError:
            self.alerts.append({
                "severity": "critical",
                "type": "uptime",
                "title": "Site is DOWN",
                "message": f"{self.target} is not responding.",
            })
        except requests.Timeout:
            self.alerts.append({
                "severity": "critical",
                "type": "uptime",
                "title": "Site timeout",
                "message": f"{self.target} timed out after 15 seconds.",
            })
        return result

    def check_ssl_expiry(self) -> dict:
        """Check SSL certificate expiry date."""
        result = {"expires": None, "days_remaining": None}
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.target) as s:
                s.settimeout(5)
                s.connect((self.target, 443))
                cert_bin = s.getpeercert(binary_form=True)

            cert = x509.load_der_x509_certificate(cert_bin, default_backend())
            expiry = cert.not_valid_after_utc
            days_left = (expiry - datetime.datetime.now(datetime.timezone.utc)).days

            result["expires"] = expiry.isoformat()
            result["days_remaining"] = days_left

            if days_left < 0:
                self.alerts.append({
                    "severity": "critical",
                    "type": "ssl_expiry",
                    "title": "SSL certificate EXPIRED",
                    "message": f"Certificate expired {abs(days_left)} days ago.",
                })
            elif days_left < 14:
                self.alerts.append({
                    "severity": "high",
                    "type": "ssl_expiry",
                    "title": "SSL certificate expiring very soon",
                    "message": f"Certificate expires in {days_left} days.",
                })
            elif days_left < 30:
                self.alerts.append({
                    "severity": "medium",
                    "type": "ssl_expiry",
                    "title": "SSL certificate expiring soon",
                    "message": f"Certificate expires in {days_left} days.",
                })
        except Exception as e:
            result["error"] = str(e)
        return result

    def check_domain_expiry(self) -> dict:
        """Check domain registration expiry."""
        result = {"expires": None, "days_remaining": None}
        try:
            w = whois.whois(self.target)
            expiry = w.expiration_date
            if isinstance(expiry, list):
                expiry = expiry[0]
            if expiry:
                if expiry.tzinfo is None:
                    days_left = (expiry - datetime.datetime.utcnow()).days
                else:
                    days_left = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
                result["expires"] = expiry.isoformat()
                result["days_remaining"] = days_left

                if days_left < 30:
                    self.alerts.append({
                        "severity": "high",
                        "type": "domain_expiry",
                        "title": "Domain expiring soon",
                        "message": f"Domain {self.target} expires in {days_left} days.",
                    })
        except Exception as e:
            result["error"] = str(e)
        return result

    def check_cve_matching(self) -> dict:
        """Check for new CVEs matching detected technologies."""
        result = {"cves": [], "technologies_detected": []}
        try:
            resp = requests.get(f"https://{self.target}", timeout=10)
            headers = resp.headers

            # Detect technologies from headers
            techs = []
            server = headers.get("Server", "")
            if server:
                techs.append(server)
            powered_by = headers.get("X-Powered-By", "")
            if powered_by:
                techs.append(powered_by)

            result["technologies_detected"] = techs

            # Query NIST NVD for each detected tech (basic keyword match)
            for tech in techs:
                keyword = tech.split("/")[0].strip().lower()
                if len(keyword) < 3:
                    continue
                try:
                    nvd_resp = requests.get(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={"keywordSearch": keyword, "resultsPerPage": 5},
                        timeout=10,
                    )
                    if nvd_resp.status_code == 200:
                        data = nvd_resp.json()
                        for vuln in data.get("vulnerabilities", [])[:3]:
                            cve = vuln.get("cve", {})
                            cve_id = cve.get("id", "")
                            descriptions = cve.get("descriptions", [])
                            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
                            result["cves"].append({"id": cve_id, "description": desc[:200]})
                except requests.RequestException:
                    continue

            if result["cves"]:
                self.alerts.append({
                    "severity": "medium",
                    "type": "cve_match",
                    "title": f"{len(result['cves'])} potential CVEs found",
                    "message": f"CVEs matching detected technologies: {', '.join(t for t in techs)}",
                })
        except requests.RequestException as e:
            result["error"] = str(e)
        return result

    def check_defacement(self, baseline_hash: str = None) -> dict:
        """Detect website content changes (defacement detection)."""
        result = {"changed": False, "current_hash": None}
        try:
            resp = requests.get(f"https://{self.target}", timeout=10)
            content_hash = hashlib.sha256(resp.text.encode()).hexdigest()
            result["current_hash"] = content_hash

            if baseline_hash and content_hash != baseline_hash:
                result["changed"] = True
                self.alerts.append({
                    "severity": "high",
                    "type": "defacement",
                    "title": "Website content changed",
                    "message": f"Content hash changed from {baseline_hash[:16]}... to {content_hash[:16]}...",
                })
        except requests.RequestException as e:
            result["error"] = str(e)
        return result
