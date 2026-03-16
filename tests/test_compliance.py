"""Tests for the ComplianceChecker — OWASP Top 10, SOC 2, and scoring logic."""

import pytest

from core.compliance import ComplianceChecker


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _checker(findings=None, checks=None):
    """Build a ComplianceChecker with pre-populated scan results."""
    scan_results = {
        "findings": findings or [],
        "checks": checks or {},
    }
    return ComplianceChecker("example.com", scan_results=scan_results)


def _ssl_finding(title="SSL certificate has expired", severity="critical"):
    return {"severity": severity, "category": "ssl_tls", "title": title}


def _header_finding(header_name):
    return {
        "severity": "medium",
        "category": "http_headers",
        "title": f"Missing header: {header_name}",
    }


def _port_finding(port=23, severity="high"):
    return {
        "severity": severity,
        "category": "port_scan",
        "title": f"Risky port open: {port}",
    }


# ---------------------------------------------------------------------------
# Score-to-grade helper
# ---------------------------------------------------------------------------

class TestScoreToGrade:
    def test_grade_a(self):
        assert ComplianceChecker._score_to_grade(95) == "A"
        assert ComplianceChecker._score_to_grade(90) == "A"

    def test_grade_b(self):
        assert ComplianceChecker._score_to_grade(85) == "B"
        assert ComplianceChecker._score_to_grade(80) == "B"

    def test_grade_c(self):
        assert ComplianceChecker._score_to_grade(75) == "C"
        assert ComplianceChecker._score_to_grade(70) == "C"

    def test_grade_d(self):
        assert ComplianceChecker._score_to_grade(65) == "D"
        assert ComplianceChecker._score_to_grade(60) == "D"

    def test_grade_f(self):
        assert ComplianceChecker._score_to_grade(59) == "F"
        assert ComplianceChecker._score_to_grade(0) == "F"


# ---------------------------------------------------------------------------
# OWASP Top 10
# ---------------------------------------------------------------------------

class TestOWASPTop10:
    def test_perfect_score_no_findings(self):
        """Clean scan results → score 100, grade A."""
        checker = _checker()
        result = checker.check_owasp_top_10()

        assert result["score"] == 100
        assert result["grade"] == "A"
        assert result["recommendations"] == []
        assert len(result["checks"]) == 10

    def test_ssl_findings_reduce_score(self):
        """SSL issues → A02 fails, score drops by 15."""
        checker = _checker(findings=[_ssl_finding()])
        result = checker.check_owasp_top_10()

        a02 = next(c for c in result["checks"] if c["id"] == "A02")
        assert a02["status"] == "fail"
        assert result["score"] <= 85

    def test_csp_missing_warns(self):
        """Missing CSP → A03 warn, score drops by 5."""
        checker = _checker(findings=[_header_finding("Content-Security-Policy")])
        result = checker.check_owasp_top_10()

        a03 = next(c for c in result["checks"] if c["id"] == "A03")
        assert a03["status"] == "warn"
        assert result["score"] <= 95

    def test_many_header_findings_fail_a05(self):
        """More than 3 missing headers → A05 fails, score drops by 15."""
        headers = ["Strict-Transport-Security", "Content-Security-Policy",
                    "X-Content-Type-Options", "X-Frame-Options"]
        checker = _checker(findings=[_header_finding(h) for h in headers])
        result = checker.check_owasp_top_10()

        a05 = next(c for c in result["checks"] if c["id"] == "A05")
        assert a05["status"] == "fail"

    def test_few_header_findings_warn_a05(self):
        """1-3 missing headers → A05 warn."""
        checker = _checker(findings=[_header_finding("X-Frame-Options")])
        result = checker.check_owasp_top_10()

        a05 = next(c for c in result["checks"] if c["id"] == "A05")
        assert a05["status"] == "warn"

    def test_server_disclosure_warns_a06(self):
        """Server version disclosed → A06 warn."""
        checker = _checker(findings=[{
            "severity": "low",
            "category": "http_headers",
            "title": "Server version disclosed",
        }])
        result = checker.check_owasp_top_10()

        a06 = next(c for c in result["checks"] if c["id"] == "A06")
        assert a06["status"] == "warn"

    def test_informational_checks_present(self):
        """A04, A07, A09, A10 are informational."""
        checker = _checker()
        result = checker.check_owasp_top_10()
        info_ids = {"A04", "A07", "A09", "A10"}
        for check in result["checks"]:
            if check["id"] in info_ids:
                assert check["status"] == "info"

    def test_score_never_below_zero(self):
        """Even with many issues, score floors at 0."""
        findings = (
            [_ssl_finding()] +
            [_header_finding(h) for h in [
                "Strict-Transport-Security", "Content-Security-Policy",
                "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection",
            ]] +
            [{"severity": "low", "category": "http_headers", "title": "Server version disclosed"}]
        )
        checker = _checker(findings=findings)
        result = checker.check_owasp_top_10()

        assert result["score"] >= 0


# ---------------------------------------------------------------------------
# SOC 2
# ---------------------------------------------------------------------------

class TestSOC2:
    def test_perfect_score(self):
        checker = _checker(checks={"ssl_tls": {"grade": "A"}})
        result = checker.check_soc2()

        assert result["score"] == 100
        assert result["grade"] == "A"

    def test_risky_ports_fail_cc61(self):
        """High-severity port findings → CC6.1 fails, -20."""
        checker = _checker(findings=[_port_finding(23, "high")])
        result = checker.check_soc2()

        cc61 = next(c for c in result["controls"] if c["id"] == "CC6.1")
        assert cc61["status"] == "fail"
        assert result["score"] <= 80

    def test_bad_ssl_fails_cc66(self):
        """SSL grade F → CC6.6 fails, -20."""
        checker = _checker(checks={"ssl_tls": {"grade": "F"}})
        result = checker.check_soc2()

        cc66 = next(c for c in result["controls"] if c["id"] == "CC6.6")
        assert cc66["status"] == "fail"
        assert result["score"] <= 80

    def test_mediocre_ssl_warns_cc66(self):
        """SSL grade B → CC6.6 warn, -10."""
        checker = _checker(checks={"ssl_tls": {"grade": "B"}})
        result = checker.check_soc2()

        cc66 = next(c for c in result["controls"] if c["id"] == "CC6.6")
        assert cc66["status"] == "warn"
        assert result["score"] == 90

    def test_missing_hsts_warns_cc67(self):
        """Missing HSTS → CC6.7 warn, -10."""
        checker = _checker(findings=[_header_finding("Strict-Transport-Security")])
        result = checker.check_soc2()

        cc67 = next(c for c in result["controls"] if c["id"] == "CC6.7")
        assert cc67["status"] == "warn"

    def test_monitoring_and_change_mgmt_info(self):
        checker = _checker()
        result = checker.check_soc2()

        cc72 = next(c for c in result["controls"] if c["id"] == "CC7.2")
        cc81 = next(c for c in result["controls"] if c["id"] == "CC8.1")
        assert cc72["status"] == "info"
        assert cc81["status"] == "info"


# ---------------------------------------------------------------------------
# GDPR
# ---------------------------------------------------------------------------

class TestGDPR:
    def test_email_findings_reduce_score(self):
        """Email security issues → GDPR-4 fails, -15."""
        checker = _checker(findings=[{
            "severity": "high", "category": "email_security", "title": "No SPF record",
        }])
        result = checker.check_gdpr()

        gdpr4 = next(c for c in result["checks"] if c["id"] == "GDPR-4")
        assert gdpr4["status"] == "fail"

    def test_critical_ssl_fails_encryption_check(self):
        """Critical SSL finding → GDPR-5 fails, -20."""
        checker = _checker(findings=[_ssl_finding(severity="critical")])
        result = checker.check_gdpr()

        gdpr5 = next(c for c in result["checks"] if c["id"] == "GDPR-5")
        assert gdpr5["status"] == "fail"


# ---------------------------------------------------------------------------
# PCI DSS
# ---------------------------------------------------------------------------

class TestPCIDSS:
    def test_perfect_score(self):
        checker = _checker(checks={"ssl_tls": {"grade": "A"}})
        result = checker.check_pci_dss()

        assert result["score"] == 100
        assert result["grade"] == "A"

    def test_risky_ports_fail_req1(self):
        checker = _checker(findings=[_port_finding()])
        result = checker.check_pci_dss()

        req1 = next(r for r in result["requirements"] if r["id"] == "1")
        assert req1["status"] == "fail"
        assert result["score"] <= 80

    def test_many_header_issues_fail_req2(self):
        headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"]
        checker = _checker(findings=[_header_finding(h) for h in headers])
        result = checker.check_pci_dss()

        req2 = next(r for r in result["requirements"] if r["id"] == "2")
        assert req2["status"] == "fail"

    def test_bad_ssl_fails_req4(self):
        checker = _checker(checks={"ssl_tls": {"grade": "F"}})
        result = checker.check_pci_dss()

        req4 = next(r for r in result["requirements"] if r["id"] == "4")
        assert req4["status"] == "fail"

    def test_mediocre_ssl_warns_req4(self):
        checker = _checker(checks={"ssl_tls": {"grade": "C"}})
        result = checker.check_pci_dss()

        req4 = next(r for r in result["requirements"] if r["id"] == "4")
        assert req4["status"] == "warn"

    def test_csp_missing_warns_req6(self):
        checker = _checker(findings=[_header_finding("Content-Security-Policy")])
        result = checker.check_pci_dss()

        req6 = next(r for r in result["requirements"] if r["id"] == "6")
        assert req6["status"] == "warn"


# ---------------------------------------------------------------------------
# ISO 27001
# ---------------------------------------------------------------------------

class TestISO27001:
    def test_perfect_score(self):
        checker = _checker(checks={"ssl_tls": {"grade": "A"}, "dns": {"dnssec": True}})
        result = checker.check_iso_27001()

        assert result["score"] == 100
        assert result["grade"] == "A"

    def test_no_dnssec_warns(self):
        checker = _checker(checks={"dns": {"dnssec": False}})
        result = checker.check_iso_27001()

        a8 = next(c for c in result["controls"] if c["id"] == "A.8")
        assert a8["status"] == "warn"

    def test_bad_ssl_fails_a10(self):
        checker = _checker(checks={"ssl_tls": {"grade": "F"}})
        result = checker.check_iso_27001()

        a10 = next(c for c in result["controls"] if c["id"] == "A.10")
        assert a10["status"] == "fail"

    def test_email_issues_fail_a13(self):
        checker = _checker(findings=[{
            "severity": "high", "category": "email_security", "title": "No DMARC",
        }])
        result = checker.check_iso_27001()

        a13 = next(c for c in result["controls"] if c["id"] == "A.13")
        assert a13["status"] == "fail"

    def test_many_headers_fail_a14(self):
        headers = ["Strict-Transport-Security", "CSP", "X-Frame-Options", "Referrer-Policy"]
        checker = _checker(findings=[_header_finding(h) for h in headers])
        result = checker.check_iso_27001()

        a14 = next(c for c in result["controls"] if c["id"] == "A.14")
        assert a14["status"] == "fail"


# ---------------------------------------------------------------------------
# run_all integration
# ---------------------------------------------------------------------------

class TestRunAll:
    def test_returns_all_frameworks(self):
        checker = _checker()
        # Patch network calls inside compliance checks
        from unittest.mock import patch
        with patch("core.compliance.requests.get", side_effect=Exception("no network")):
            result = checker.run_all()

        assert result["target"] == "example.com"
        assert "timestamp" in result
        frameworks = result["frameworks"]
        assert set(frameworks.keys()) == {"owasp_top_10", "soc2", "gdpr", "pci_dss", "iso_27001"}

        for name, data in frameworks.items():
            assert "score" in data
            assert "grade" in data
            assert 0 <= data["score"] <= 100
            assert data["grade"] in ("A", "B", "C", "D", "F")
