"""Tests for the InfrastructureScanner — port scan, SSL check, header audit."""

import datetime
import socket
import ssl
from unittest.mock import patch, MagicMock

import pytest
import requests

from core.scanner import InfrastructureScanner


# ---------------------------------------------------------------------------
# Target normalisation
# ---------------------------------------------------------------------------

class TestTargetNormalization:
    def test_strips_https(self):
        s = InfrastructureScanner("https://example.com")
        assert s.target == "example.com"

    def test_strips_http(self):
        s = InfrastructureScanner("http://example.com")
        assert s.target == "example.com"

    def test_strips_trailing_slash(self):
        s = InfrastructureScanner("example.com/")
        assert s.target == "example.com"

    def test_lowercases(self):
        s = InfrastructureScanner("EXAMPLE.COM")
        assert s.target == "example.com"

    def test_strips_whitespace(self):
        s = InfrastructureScanner("  example.com  ")
        assert s.target == "example.com"

    def test_domain_extracted(self):
        s = InfrastructureScanner("https://sub.example.com/path")
        assert s.domain == "sub.example.com"


# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------

class TestPortScan:
    def _scanner(self):
        return InfrastructureScanner("example.com")

    @patch("socket.socket")
    def test_detects_open_port(self, mock_socket_cls):
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst
        # connect_ex returns 0 → port open
        sock_inst.connect_ex.return_value = 0

        scanner = self._scanner()
        result = scanner.scan_ports()

        assert len(result["open_ports"]) > 0
        assert result["total_scanned"] == 19  # 19 common ports

    @patch("socket.socket")
    def test_all_closed(self, mock_socket_cls):
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst
        sock_inst.connect_ex.return_value = 1  # port closed

        scanner = self._scanner()
        result = scanner.scan_ports()

        assert result["open_ports"] == []
        assert scanner.findings == []

    @patch("socket.socket")
    def test_risky_port_creates_finding(self, mock_socket_cls):
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst

        # Only port 23 (Telnet) will be open
        def fake_connect(addr):
            return 0 if addr[1] == 23 else 1

        sock_inst.connect_ex.side_effect = fake_connect

        scanner = self._scanner()
        scanner.scan_ports()

        assert len(scanner.findings) == 1
        f = scanner.findings[0]
        assert f["severity"] == "high"
        assert f["category"] == "port_scan"
        assert "23" in f["title"]

    @patch("socket.socket")
    def test_medium_severity_risky_port(self, mock_socket_cls):
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst

        def fake_connect(addr):
            return 0 if addr[1] == 6379 else 1  # Redis

        sock_inst.connect_ex.side_effect = fake_connect

        scanner = self._scanner()
        scanner.scan_ports()

        assert len(scanner.findings) == 1
        assert scanner.findings[0]["severity"] == "medium"

    @patch("socket.socket")
    def test_timeout_handled(self, mock_socket_cls):
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst
        sock_inst.connect_ex.side_effect = socket.timeout("timed out")

        scanner = self._scanner()
        result = scanner.scan_ports()

        assert result["open_ports"] == []


# ---------------------------------------------------------------------------
# SSL / TLS checks
# ---------------------------------------------------------------------------

class TestSSLCheck:
    def _scanner(self):
        return InfrastructureScanner("example.com")

    @patch("core.scanner.x509")
    @patch("core.scanner.ssl.create_default_context")
    def test_valid_cert_grade_a(self, mock_ctx_factory, mock_x509):
        # Wire up the SSL context / socket chain
        mock_ctx = MagicMock()
        mock_ctx_factory.return_value = mock_ctx
        mock_sock = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        mock_sock.getpeercert.side_effect = [b"certbytes", {"issuer": [], "subject": []}]
        mock_sock.version.return_value = "TLSv1.3"

        mock_cert = MagicMock()
        mock_cert.not_valid_after_utc = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=90)
        mock_x509.load_der_x509_certificate.return_value = mock_cert

        scanner = self._scanner()
        result = scanner.check_ssl_tls()

        assert result["grade"] == "A"
        assert result["expires_in_days"] >= 89
        assert not any(f["category"] == "ssl_tls" for f in scanner.findings)

    @patch("core.scanner.x509")
    @patch("core.scanner.ssl.create_default_context")
    def test_expired_cert_grade_f(self, mock_ctx_factory, mock_x509):
        mock_ctx = MagicMock()
        mock_ctx_factory.return_value = mock_ctx
        mock_sock = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        mock_sock.getpeercert.side_effect = [b"certbytes", {"issuer": [], "subject": []}]
        mock_sock.version.return_value = "TLSv1.3"

        mock_cert = MagicMock()
        mock_cert.not_valid_after_utc = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)
        mock_x509.load_der_x509_certificate.return_value = mock_cert

        scanner = self._scanner()
        result = scanner.check_ssl_tls()

        assert result["grade"] == "F"
        assert any(f["severity"] == "critical" and "expired" in f["title"] for f in scanner.findings)

    @patch("core.scanner.x509")
    @patch("core.scanner.ssl.create_default_context")
    def test_expiring_soon_grade_b(self, mock_ctx_factory, mock_x509):
        mock_ctx = MagicMock()
        mock_ctx_factory.return_value = mock_ctx
        mock_sock = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        mock_sock.getpeercert.side_effect = [b"certbytes", {"issuer": [], "subject": []}]
        mock_sock.version.return_value = "TLSv1.3"

        mock_cert = MagicMock()
        mock_cert.not_valid_after_utc = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=15)
        mock_x509.load_der_x509_certificate.return_value = mock_cert

        scanner = self._scanner()
        result = scanner.check_ssl_tls()

        assert result["grade"] == "B"
        assert any("expiring soon" in f["title"] for f in scanner.findings)

    @patch("core.scanner.x509")
    @patch("core.scanner.ssl.create_default_context")
    def test_weak_protocol_grade_c(self, mock_ctx_factory, mock_x509):
        mock_ctx = MagicMock()
        mock_ctx_factory.return_value = mock_ctx
        mock_sock = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        mock_sock.getpeercert.side_effect = [b"certbytes", {"issuer": [], "subject": []}]
        mock_sock.version.return_value = "TLSv1"

        mock_cert = MagicMock()
        mock_cert.not_valid_after_utc = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=90)
        mock_x509.load_der_x509_certificate.return_value = mock_cert

        scanner = self._scanner()
        result = scanner.check_ssl_tls()

        assert result["grade"] == "C"
        assert any(f["severity"] == "high" and "Weak TLS" in f["title"] for f in scanner.findings)

    @patch("core.scanner.ssl.create_default_context")
    def test_ssl_error_creates_critical_finding(self, mock_ctx_factory):
        mock_ctx = MagicMock()
        mock_ctx_factory.return_value = mock_ctx
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(
            side_effect=ssl.SSLError("certificate verify failed")
        )
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        scanner = self._scanner()
        result = scanner.check_ssl_tls()

        assert result["grade"] == "F"
        assert any(f["severity"] == "critical" for f in scanner.findings)


# ---------------------------------------------------------------------------
# HTTP header audit
# ---------------------------------------------------------------------------

class TestHTTPHeaders:
    def _scanner(self):
        return InfrastructureScanner("example.com")

    @patch("core.scanner.requests.get")
    def test_all_headers_present(self, mock_get):
        resp = MagicMock()
        resp.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
        }
        mock_get.return_value = resp

        scanner = self._scanner()
        result = scanner.check_http_headers()

        assert result["score"] == 100
        assert result["missing"] == []
        assert len(result["present"]) == 7
        assert not any(f["category"] == "http_headers" for f in scanner.findings)

    @patch("core.scanner.requests.get")
    def test_all_headers_missing(self, mock_get):
        resp = MagicMock()
        resp.headers = {}
        mock_get.return_value = resp

        scanner = self._scanner()
        result = scanner.check_http_headers()

        assert result["score"] == 0
        assert len(result["missing"]) == 7
        header_findings = [f for f in scanner.findings if f["category"] == "http_headers"]
        assert len(header_findings) == 7

    @patch("core.scanner.requests.get")
    def test_server_version_disclosure(self, mock_get):
        resp = MagicMock()
        resp.headers = {"Server": "nginx/1.21.0"}
        mock_get.return_value = resp

        scanner = self._scanner()
        scanner.check_http_headers()

        assert any("Server version disclosed" in f["title"] for f in scanner.findings)

    @patch("core.scanner.requests.get")
    def test_partial_headers(self, mock_get):
        resp = MagicMock()
        resp.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }
        mock_get.return_value = resp

        scanner = self._scanner()
        result = scanner.check_http_headers()

        assert result["score"] == 43  # 3/7 ≈ 43%
        assert len(result["present"]) == 3
        assert len(result["missing"]) == 4

    @patch("core.scanner.requests.get")
    def test_request_exception_handled(self, mock_get):
        mock_get.side_effect = requests.RequestException("Connection refused")

        scanner = self._scanner()
        result = scanner.check_http_headers()

        assert "error" in result


# ---------------------------------------------------------------------------
# run_all integration
# ---------------------------------------------------------------------------

class TestRunAll:
    @patch.object(InfrastructureScanner, "check_subdomain_takeover", return_value={"checked": [], "vulnerable": []})
    @patch.object(InfrastructureScanner, "check_open_redirect", return_value={"vulnerable": False})
    @patch.object(InfrastructureScanner, "check_email_security", return_value={"spf": None, "dmarc": None, "dkim": None})
    @patch.object(InfrastructureScanner, "check_dns", return_value={"records": {}})
    @patch.object(InfrastructureScanner, "check_http_headers", return_value={"score": 50})
    @patch.object(InfrastructureScanner, "check_ssl_tls", return_value={"grade": "A"})
    @patch.object(InfrastructureScanner, "scan_ports", return_value={"open_ports": []})
    def test_run_all_returns_all_checks(self, *_):
        scanner = InfrastructureScanner("example.com")
        results = scanner.run_all()

        assert results["target"] == "example.com"
        assert "timestamp" in results
        assert set(results["checks"].keys()) == {
            "port_scan", "ssl_tls", "http_headers", "dns",
            "email_security", "open_redirect", "subdomain_takeover",
        }

    def test_run_all_catches_exceptions(self):
        scanner = InfrastructureScanner("example.com")
        with patch.object(scanner, "scan_ports", side_effect=RuntimeError("boom")):
            with patch.object(scanner, "check_ssl_tls", return_value={"grade": "A"}):
                with patch.object(scanner, "check_http_headers", return_value={}):
                    with patch.object(scanner, "check_dns", return_value={}):
                        with patch.object(scanner, "check_email_security", return_value={}):
                            with patch.object(scanner, "check_open_redirect", return_value={}):
                                with patch.object(scanner, "check_subdomain_takeover", return_value={}):
                                    results = scanner.run_all()

        assert results["checks"]["port_scan"]["status"] == "error"
        assert "boom" in results["checks"]["port_scan"]["error"]
