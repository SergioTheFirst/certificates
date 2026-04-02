"""Tests for net_cert_scanner.models."""

from datetime import datetime

import pytest

from net_cert_scanner.models import CertInfo, HostInfo, ScanError, ScanResult


def _make_cert(days_left: int, status: str = "ok") -> CertInfo:
    now = datetime(2025, 4, 2)
    return CertInfo(
        thumbprint="AABBCC",
        subject="CN=Test",
        issuer="CN=CA",
        not_after=now,
        not_before=now,
        days_left=days_left,
        status=status,
    )


def _make_host(ip: str, certs: list) -> HostInfo:
    return HostInfo(ip=ip, hostname=f"PC-{ip}", certs=certs)


class TestCertInfo:
    def test_status_default_empty(self):
        cert = _make_cert(10)
        assert cert.status == "ok"

    def test_fields_accessible(self):
        cert = _make_cert(-5, status="expired")
        assert cert.days_left == -5
        assert cert.status == "expired"


class TestHostInfo:
    def test_problematic_certs_filters_ok(self):
        certs = [
            _make_cert(100, "ok"),
            _make_cert(5, "expiring"),
            _make_cert(-1, "expired"),
        ]
        host = _make_host("192.168.1.1", certs)
        problematic = host.problematic_certs
        assert len(problematic) == 2
        assert all(c.status != "ok" for c in problematic)

    def test_problematic_certs_empty_when_all_ok(self):
        certs = [_make_cert(100, "ok"), _make_cert(200, "ok")]
        host = _make_host("192.168.1.2", certs)
        assert host.problematic_certs == []


class TestScanResult:
    def test_counts_with_mixed_certs(self):
        host1 = _make_host("1.1.1.1", [
            _make_cert(-3, "expired"),
            _make_cert(10, "expiring"),
            _make_cert(100, "ok"),
        ])
        host2 = _make_host("1.1.1.2", [
            _make_cert(20, "expiring"),
        ])
        result = ScanResult(
            timestamp=datetime.now(),
            hosts=[host1, host2],
            errors=[ScanError(ip="1.1.1.3", reason="timeout")],
        )

        assert result.expired_count == 1
        assert result.expiring_count == 2
        assert result.successful == 2
        assert result.failed == 1
        assert result.total_discovered == 3

    def test_empty_result(self):
        result = ScanResult(timestamp=datetime.now())
        assert result.expired_count == 0
        assert result.expiring_count == 0
        assert result.total_discovered == 0
        assert result.all_problematic == []

    def test_all_problematic_pairs(self):
        certs = [_make_cert(-1, "expired"), _make_cert(5, "expiring")]
        host = _make_host("10.0.0.1", certs)
        result = ScanResult(timestamp=datetime.now(), hosts=[host])

        pairs = result.all_problematic
        assert len(pairs) == 2
        for h, c in pairs:
            assert h is host
            assert c.status in ("expired", "expiring")
