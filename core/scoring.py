"""
Cerberus SMB Security Scoring Engine

A scoring methodology designed specifically for small and medium businesses.
Produces a composite security score (0-100) from five weighted dimensions:
Infrastructure, Authentication, Compliance, Monitoring, and Human Factor.
"""

from dataclasses import dataclass, field
from typing import Optional


# Dimension weights (must sum to 1.0)
DIMENSION_WEIGHTS = {
    "infrastructure": 0.30,
    "authentication": 0.25,
    "compliance": 0.20,
    "monitoring": 0.15,
    "human_factor": 0.10,
}

# Score interpretation thresholds
SCORE_RATINGS = [
    (90, "Excellent", "Enterprise-grade security posture"),
    (75, "Good", "Strong fundamentals with minor gaps"),
    (60, "Fair", "Common SMB level — fixable gaps exist"),
    (40, "Poor", "Significant exposure — action needed"),
    (0, "Critical", "High breach risk — emergency assessment recommended"),
]

# SSL/TLS grade scoring
SSL_GRADE_SCORES = {
    "A+": 25, "A": 22, "A-": 20,
    "B": 15, "B-": 12,
    "C": 8, "C-": 5,
    "D": 2, "F": 0, "T": 0, "N/A": 0,
}

# HTTP security headers and their point values
SECURITY_HEADERS = {
    "strict-transport-security": 4,
    "content-security-policy": 4,
    "x-frame-options": 4,
    "x-content-type-options": 4,
    "referrer-policy": 4,
}


@dataclass
class InfrastructureScore:
    """Scores infrastructure security (ports, SSL, headers, DNS)."""

    port_exposure: float = 0.0       # 0-25
    ssl_tls_grade: float = 0.0       # 0-25
    http_headers: float = 0.0        # 0-20
    dns_security: float = 0.0        # 0-15
    subdomain_hygiene: float = 0.0   # 0-15

    @property
    def total(self) -> float:
        return min(100.0, self.port_exposure + self.ssl_tls_grade +
                   self.http_headers + self.dns_security + self.subdomain_hygiene)


@dataclass
class AuthenticationScore:
    """Scores authentication and access control posture."""

    password_policy: float = 0.0     # 0-30
    mfa_adoption: float = 0.0        # 0-30
    sso_config: float = 0.0          # 0-20
    session_management: float = 0.0  # 0-20

    @property
    def total(self) -> float:
        return min(100.0, self.password_policy + self.mfa_adoption +
                   self.sso_config + self.session_management)


@dataclass
class ComplianceScore:
    """Scores compliance across multiple frameworks."""

    owasp_top10: float = 0.0    # 0-100
    soc2_readiness: float = 0.0  # 0-100
    gdpr_exposure: float = 0.0   # 0-100
    pci_dss: float = 0.0         # 0-100
    iso_27001: float = 0.0       # 0-100

    @property
    def total(self) -> float:
        scores = [self.owasp_top10, self.soc2_readiness, self.gdpr_exposure,
                  self.pci_dss, self.iso_27001]
        active = [s for s in scores if s > 0]
        return sum(active) / len(active) if active else 0.0


@dataclass
class MonitoringScore:
    """Scores monitoring and continuous assessment coverage."""

    uptime_tracking: float = 0.0      # 0-25
    cert_expiry_watch: float = 0.0    # 0-25
    cve_monitoring: float = 0.0       # 0-25
    breach_monitoring: float = 0.0    # 0-25

    @property
    def total(self) -> float:
        return min(100.0, self.uptime_tracking + self.cert_expiry_watch +
                   self.cve_monitoring + self.breach_monitoring)


@dataclass
class HumanFactorScore:
    """Scores human-related security exposure."""

    email_exposure: float = 0.0       # 0-40
    breach_history: float = 0.0       # 0-30
    awareness_indicators: float = 0.0  # 0-30

    @property
    def total(self) -> float:
        return min(100.0, self.email_exposure + self.breach_history +
                   self.awareness_indicators)


@dataclass
class SecurityAssessment:
    """Complete SMB security assessment with composite scoring."""

    target: str
    infrastructure: InfrastructureScore = field(default_factory=InfrastructureScore)
    authentication: AuthenticationScore = field(default_factory=AuthenticationScore)
    compliance: ComplianceScore = field(default_factory=ComplianceScore)
    monitoring: MonitoringScore = field(default_factory=MonitoringScore)
    human_factor: HumanFactorScore = field(default_factory=HumanFactorScore)

    @property
    def composite_score(self) -> float:
        """Calculate weighted composite security score (0-100)."""
        return round(
            self.infrastructure.total * DIMENSION_WEIGHTS["infrastructure"] +
            self.authentication.total * DIMENSION_WEIGHTS["authentication"] +
            self.compliance.total * DIMENSION_WEIGHTS["compliance"] +
            self.monitoring.total * DIMENSION_WEIGHTS["monitoring"] +
            self.human_factor.total * DIMENSION_WEIGHTS["human_factor"],
            1
        )

    @property
    def rating(self) -> tuple:
        """Return (label, description) for the current composite score."""
        score = self.composite_score
        for threshold, label, description in SCORE_RATINGS:
            if score >= threshold:
                return label, description
        return "Critical", "High breach risk"

    def dimension_breakdown(self) -> dict:
        """Return all dimension scores with weights."""
        return {
            "infrastructure": {
                "score": round(self.infrastructure.total, 1),
                "weight": DIMENSION_WEIGHTS["infrastructure"],
                "weighted": round(self.infrastructure.total * DIMENSION_WEIGHTS["infrastructure"], 1),
            },
            "authentication": {
                "score": round(self.authentication.total, 1),
                "weight": DIMENSION_WEIGHTS["authentication"],
                "weighted": round(self.authentication.total * DIMENSION_WEIGHTS["authentication"], 1),
            },
            "compliance": {
                "score": round(self.compliance.total, 1),
                "weight": DIMENSION_WEIGHTS["compliance"],
                "weighted": round(self.compliance.total * DIMENSION_WEIGHTS["compliance"], 1),
            },
            "monitoring": {
                "score": round(self.monitoring.total, 1),
                "weight": DIMENSION_WEIGHTS["monitoring"],
                "weighted": round(self.monitoring.total * DIMENSION_WEIGHTS["monitoring"], 1),
            },
            "human_factor": {
                "score": round(self.human_factor.total, 1),
                "weight": DIMENSION_WEIGHTS["human_factor"],
                "weighted": round(self.human_factor.total * DIMENSION_WEIGHTS["human_factor"], 1),
            },
        }


def score_port_exposure(open_ports: list, required_ports: list) -> float:
    """Score port exposure: 25 points max, -3 per unnecessary open port."""
    unnecessary = [p for p in open_ports if p not in required_ports]
    return max(0.0, 25.0 - (len(unnecessary) * 3.0))


def score_ssl_grade(grade: str) -> float:
    """Convert SSL/TLS letter grade to numeric score (0-25)."""
    return float(SSL_GRADE_SCORES.get(grade.upper(), 0))


def score_security_headers(headers: dict) -> float:
    """Score HTTP security headers presence (0-20)."""
    score = 0.0
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for header, points in SECURITY_HEADERS.items():
        if header in lower_headers:
            score += points
    return min(20.0, score)


def score_dns_security(spf: bool, dkim: bool, dmarc_policy: Optional[str]) -> float:
    """Score DNS security controls (SPF, DKIM, DMARC). Max 15 points."""
    score = 0.0
    if spf:
        score += 5.0
    if dkim:
        score += 5.0
    if dmarc_policy:
        policy = dmarc_policy.lower()
        if policy == "reject":
            score += 5.0
        elif policy == "quarantine":
            score += 3.0
        elif policy == "none":
            score += 1.0
    return score


def score_owasp_top10(results: dict) -> float:
    """
    Score OWASP Top 10 compliance.

    Args:
        results: dict mapping OWASP category to 'pass', 'fail', or 'partial'

    Returns:
        Score 0-100
    """
    score = 0.0
    for category, result in results.items():
        if result == "pass":
            score += 10.0
        elif result == "partial":
            score += 5.0
    return min(100.0, score)
