"""Tests for net_cert_scanner.analyzer."""

from datetime import datetime, timezone

import pytest

from net_cert_scanner.analyzer import analyze, classify_cert
from net_cert_scanner.models import CertInfo, HostInfo, ScanResult


def _cert(days_left: int) -> CertInfo:
    now = datetime(2025, 4, 2)
    return CertInfo(
        thumbprint="AA",
        subject="CN=Test",
        issuer="CN=CA",
        not_after=now,
        not_before=now,
        days_left=days_left,
    )


NOW = datetime(2025, 4, 2)


class TestClassifyCert:
    def test_expired_when_days_negative(self):
        assert classify_cert(_cert(-1), threshold_days=30, now=NOW) == "expired"

    def test_expired_at_minus_100(self):
        assert classify_cert(_cert(-100), threshold_days=30, now=NOW) == "expired"

    def test_expiring_at_zero(self):
        assert classify_cert(_cert(0), threshold_days=30, now=NOW) == "expiring"

    def test_expiring_at_threshold(self):
        assert classify_cert(_cert(30), threshold_days=30, now=NOW) == "expiring"

    def test_ok_above_threshold(self):
        assert classify_cert(_cert(31), threshold_days=30, now=NOW) == "ok"

    def test_ok_far_future(self):
        assert classify_cert(_cert(365), threshold_days=30, now=NOW) == "ok"

    def test_threshold_zero_only_expired_is_not_ok(self):
        # threshold=0: only days_left<0 → expired; days_left=0 → expiring
        assert classify_cert(_cert(-1), threshold_days=0, now=NOW) == "expired"
        assert classify_cert(_cert(0), threshold_days=0, now=NOW) == "expiring"
        assert classify_cert(_cert(1), threshold_days=0, now=NOW) == "ok"


class TestAnalyze:
    def _make_result(self, certs_days: list[int]) -> ScanResult:
        host = HostInfo(
            ip="10.0.0.1",
            hostname="PC001",
            certs=[_cert(d) for d in certs_days],
        )
        return ScanResult(timestamp=datetime.now(), hosts=[host])

    def test_all_certs_get_status(self):
        result = self._make_result([-5, 10, 100])
        analyze(result, threshold_days=30)
        statuses = [c.status for c in result.hosts[0].certs]
        assert statuses == ["expired", "expiring", "ok"]

    def test_counts_match_after_analyze(self):
        result = self._make_result([-3, -1, 15, 25, 60, 90])
        analyze(result, threshold_days=30)
        assert result.expired_count == 2
        assert result.expiring_count == 2

    def test_empty_host_no_crash(self):
        result = self._make_result([])
        analyze(result, threshold_days=30)
        assert result.expired_count == 0
        assert result.expiring_count == 0

    def test_modifies_in_place(self):
        result = self._make_result([5])
        cert = result.hosts[0].certs[0]
        assert cert.status == ""  # before analyze
        analyze(result, threshold_days=30)
        assert cert.status == "expiring"

    def test_multiple_hosts(self):
        h1 = HostInfo(ip="1.1.1.1", certs=[_cert(-1), _cert(100)])
        h2 = HostInfo(ip="1.1.1.2", certs=[_cert(5), _cert(15), _cert(200)])
        result = ScanResult(timestamp=datetime.now(), hosts=[h1, h2])
        analyze(result, threshold_days=30)
        assert result.expired_count == 1
        assert result.expiring_count == 2
