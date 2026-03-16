"""AI Security Advisor — analyzes findings, prioritizes by business impact, generates recommendations."""

import datetime
import json

from core.config import Config

try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False


class AIAdvisor:
    """AI-powered security advisor that analyzes findings and generates actionable recommendations."""

    PRIORITY_WEIGHTS = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 1,
    }

    def __init__(self, scan_results: dict = None, compliance_results: dict = None, breach_results: dict = None):
        self.scan_results = scan_results or {}
        self.compliance_results = compliance_results or {}
        self.breach_results = breach_results or {}

    def analyze(self) -> dict:
        """Run full analysis and generate recommendations."""
        findings = self._collect_findings()
        prioritized = self._prioritize_findings(findings)
        recommendations = self._generate_recommendations(prioritized)
        playbooks = self._generate_playbooks(prioritized[:5])
        summary = self._generate_summary(prioritized)

        return {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "total_findings": len(findings),
            "risk_score": self._calculate_risk_score(findings),
            "prioritized_findings": prioritized[:20],
            "recommendations": recommendations,
            "playbooks": playbooks,
            "summary": summary,
        }

    def _collect_findings(self) -> list:
        """Collect all findings from scan, compliance, and breach results."""
        findings = []

        # From scanner
        for f in self.scan_results.get("findings", []):
            findings.append({**f, "source": "infrastructure_scan"})

        # From compliance
        for framework, data in self.compliance_results.get("frameworks", {}).items():
            for rec in data.get("recommendations", []):
                findings.append({
                    "severity": "medium",
                    "category": "compliance",
                    "title": f"[{framework.upper()}] {rec}",
                    "description": rec,
                    "source": f"compliance_{framework}",
                })

        # From breach monitoring
        for alert in self.breach_results.get("alerts", []):
            findings.append({
                "severity": alert.get("severity", "medium"),
                "category": "breach",
                "title": alert.get("title", ""),
                "description": alert.get("message", ""),
                "source": "breach_monitoring",
            })

        return findings

    def _prioritize_findings(self, findings: list) -> list:
        """Prioritize findings by business impact."""
        for f in findings:
            severity = f.get("severity", "low")
            weight = self.PRIORITY_WEIGHTS.get(severity, 1)

            # Boost certain categories
            category = f.get("category", "")
            if category in ("breach", "ssl_tls"):
                weight *= 1.5
            elif category == "email_security":
                weight *= 1.3

            f["priority_score"] = weight

        return sorted(findings, key=lambda x: x["priority_score"], reverse=True)

    def _generate_recommendations(self, prioritized: list) -> list:
        """Generate plain-language recommendations."""
        recommendations = []
        seen_categories = set()

        for f in prioritized:
            cat = f.get("category", "unknown")
            if cat in seen_categories:
                continue
            seen_categories.add(cat)

            rec = {
                "priority": "high" if f["priority_score"] >= 7 else "medium" if f["priority_score"] >= 4 else "low",
                "category": cat,
                "title": f"Address {cat.replace('_', ' ').title()} Issues",
                "description": f.get("remediation", f.get("description", "")),
                "estimated_effort": self._estimate_effort(f),
                "business_impact": self._assess_impact(f),
            }
            recommendations.append(rec)

        return recommendations

    def _generate_playbooks(self, top_findings: list) -> list:
        """Generate remediation playbooks for top findings."""
        playbooks = []
        playbook_templates = {
            "ssl_tls": {
                "title": "SSL/TLS Remediation Playbook",
                "steps": [
                    "Audit current SSL/TLS configuration using testssl.sh or SSL Labs",
                    "Disable TLS 1.0 and TLS 1.1 on all servers",
                    "Configure TLS 1.2 with strong cipher suites (ECDHE+AESGCM)",
                    "Enable TLS 1.3 where supported",
                    "Set up automatic certificate renewal (Let's Encrypt + certbot)",
                    "Enable HSTS with includeSubDomains and preload",
                    "Test configuration with SSL Labs (aim for A+ grade)",
                ],
            },
            "http_headers": {
                "title": "Security Headers Remediation Playbook",
                "steps": [
                    "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    "Implement Content-Security-Policy starting with report-only mode",
                    "Add X-Content-Type-Options: nosniff",
                    "Add X-Frame-Options: DENY (or SAMEORIGIN if iframes needed)",
                    "Add Referrer-Policy: strict-origin-when-cross-origin",
                    "Add Permissions-Policy to disable unused browser features",
                    "Test all headers at securityheaders.com",
                ],
            },
            "email_security": {
                "title": "Email Security Remediation Playbook",
                "steps": [
                    "Create/update SPF record with all authorized senders, end with -all",
                    "Generate and publish DKIM keys for your email provider",
                    "Create DMARC record: start with p=none for monitoring",
                    "Monitor DMARC reports for 2-4 weeks",
                    "Gradually move DMARC to p=quarantine then p=reject",
                    "Verify all records with MXToolbox or dmarcian",
                ],
            },
            "port_scan": {
                "title": "Network Hardening Playbook",
                "steps": [
                    "Audit all open ports and identify unnecessary services",
                    "Close all non-essential ports at the firewall level",
                    "Move administrative services (SSH, databases) behind VPN",
                    "Implement network segmentation for sensitive services",
                    "Set up fail2ban or similar for SSH brute-force protection",
                    "Enable logging for all firewall deny rules",
                    "Schedule regular port scans to detect drift",
                ],
            },
            "breach": {
                "title": "Breach Response Playbook",
                "steps": [
                    "Identify all affected accounts from breach data",
                    "Force password reset for compromised accounts",
                    "Enable MFA for all affected and privileged accounts",
                    "Review account activity logs for signs of unauthorized access",
                    "Notify affected employees per company policy",
                    "Update credentials for any shared/service accounts",
                    "Enroll in continuous breach monitoring",
                ],
            },
        }

        for f in top_findings:
            cat = f.get("category", "")
            if cat in playbook_templates:
                playbook = playbook_templates[cat].copy()
                playbook["finding"] = f.get("title", "")
                playbook["severity"] = f.get("severity", "medium")
                playbooks.append(playbook)

        return playbooks

    def _generate_summary(self, prioritized: list) -> dict:
        """Generate a monthly security summary."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in prioritized:
            sev = f.get("severity", "low")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Overall risk level
        if severity_counts["critical"] > 0:
            risk_level = "CRITICAL"
        elif severity_counts["high"] > 2:
            risk_level = "HIGH"
        elif severity_counts["high"] > 0:
            risk_level = "MODERATE"
        elif severity_counts["medium"] > 3:
            risk_level = "MODERATE"
        else:
            risk_level = "LOW"

        return {
            "risk_level": risk_level,
            "severity_breakdown": severity_counts,
            "total_findings": len(prioritized),
            "top_3_actions": [f.get("title", "") for f in prioritized[:3]],
            "compliance_scores": {
                framework: data.get("score", 0)
                for framework, data in self.compliance_results.get("frameworks", {}).items()
            },
        }

    def generate_ai_summary(self, prioritized: list) -> str:
        """Use OpenAI to generate a natural-language executive summary."""
        if not HAS_OPENAI or not Config.OPENAI_API_KEY:
            return self._generate_fallback_summary(prioritized)

        client = openai.OpenAI(api_key=Config.OPENAI_API_KEY)
        prompt = (
            "You are a cybersecurity advisor for a small business. "
            "Analyze these security findings and write a brief, plain-language executive summary. "
            "Focus on business impact and actionable next steps. Be concise.\n\n"
            f"Findings:\n{json.dumps(prioritized[:10], indent=2)}"
        )

        try:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500,
            )
            return response.choices[0].message.content
        except Exception:
            return self._generate_fallback_summary(prioritized)

    def _generate_fallback_summary(self, prioritized: list) -> str:
        """Generate a summary without AI."""
        critical = [f for f in prioritized if f.get("severity") == "critical"]
        high = [f for f in prioritized if f.get("severity") == "high"]

        parts = [f"Security scan found {len(prioritized)} issue(s)."]
        if critical:
            parts.append(f"{len(critical)} CRITICAL issue(s) require immediate attention: "
                         + ", ".join(f["title"] for f in critical[:3]) + ".")
        if high:
            parts.append(f"{len(high)} high-severity issue(s) should be addressed this week.")
        if not critical and not high:
            parts.append("No critical or high-severity issues found. Good security posture overall.")
        return " ".join(parts)

    @staticmethod
    def _calculate_risk_score(findings: list) -> int:
        """Calculate overall risk score (0-100, higher = more risk)."""
        if not findings:
            return 0
        weights = {"critical": 25, "high": 15, "medium": 5, "low": 1}
        total = sum(weights.get(f.get("severity", "low"), 1) for f in findings)
        return min(100, total)

    @staticmethod
    def _estimate_effort(finding: dict) -> str:
        category = finding.get("category", "")
        effort_map = {
            "http_headers": "Low (1-2 hours)",
            "ssl_tls": "Low (1-3 hours)",
            "email_security": "Medium (2-4 hours)",
            "port_scan": "Medium (2-4 hours)",
            "dns": "Low (30 minutes)",
            "breach": "High (4-8 hours)",
            "compliance": "High (varies)",
        }
        return effort_map.get(category, "Medium (2-4 hours)")

    @staticmethod
    def _assess_impact(finding: dict) -> str:
        severity = finding.get("severity", "low")
        impact_map = {
            "critical": "Immediate risk of data breach or service compromise",
            "high": "Significant security weakness that could be exploited",
            "medium": "Security gap that increases attack surface",
            "low": "Minor issue with limited direct impact",
        }
        return impact_map.get(severity, "Unknown impact")
