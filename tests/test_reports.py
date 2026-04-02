"""Tests for net_cert_scanner.reports."""

import csv
import json
from datetime import datetime
from pathlib import Path

import pytest

from net_cert_scanner.models import CertInfo, HostInfo, ScanError, ScanResult
from net_cert_scanner.reports import (
    build_scan_json,
    save_errors_log,
    save_full_json,
    save_problem_csv,
    save_summary_json,
)


def _make_scan_result() -> ScanResult:
    cert_expired = CertInfo(
        thumbprint="EXP123",
        subject="CN=John Doe, O=Acme",
        issuer="CN=Corp-CA",
        not_after=datetime(2025, 1, 1),
        not_before=datetime(2024, 1, 1),
        days_left=-91,
        status="expired",
    )
    cert_expiring = CertInfo(
        thumbprint="EXP456",
        subject="CN=Jane Smith",
        issuer="CN=Corp-CA",
        not_after=datetime(2025, 4, 20),
        not_before=datetime(2024, 4, 20),
        days_left=18,
        status="expiring",
    )
    cert_ok = CertInfo(
        thumbprint="OK789",
        subject="CN=Service Account",
        issuer="CN=Corp-CA",
        not_after=datetime(2026, 1, 1),
        not_before=datetime(2025, 1, 1),
        days_left=275,
        status="ok",
    )
    host = HostInfo(
        ip="192.168.1.10",
        hostname="PC-FINANCE",
        mac="AA:BB:CC:DD:EE:FF",
        certs=[cert_expired, cert_expiring, cert_ok],
    )
    error = ScanError(
        ip="192.168.1.50",
        hostname="",
        method="wmiexec",
        reason="Access denied",
    )
    return ScanResult(
        timestamp=datetime(2025, 4, 2, 14, 30, 0),
        scan_range="192.168.1.0/24",
        hosts=[host],
        errors=[error],
    )


class TestBuildScanJson:
    def test_structure_keys(self):
        result = _make_scan_result()
        data = build_scan_json(result)
        assert "timestamp" in data
        assert "summary" in data
        assert "problematic_certs" in data
        assert "hosts" in data
        assert "errors" in data

    def test_summary_counts(self):
        result = _make_scan_result()
        data = build_scan_json(result)
        s = data["summary"]
        assert s["expired"] == 1
        assert s["expiring"] == 1
        assert s["successful"] == 1
        assert s["failed"] == 1

    def test_problematic_certs_excludes_ok(self):
        result = _make_scan_result()
        data = build_scan_json(result)
        statuses = [c["status"] for c in data["problematic_certs"]]
        assert "ok" not in statuses
        assert len(data["problematic_certs"]) == 2

    def test_hosts_include_all_certs(self):
        result = _make_scan_result()
        data = build_scan_json(result)
        assert len(data["hosts"]) == 1
        assert data["hosts"][0]["total_certs"] == 3

    def test_no_password_in_output(self):
        result = _make_scan_result()
        raw = json.dumps(build_scan_json(result))
        assert "secret" not in raw.lower()
        assert "password" not in raw.lower()


class TestSaveProblemCsv:
    def test_creates_file(self, tmp_path):
        result = _make_scan_result()
        path = tmp_path / "out.csv"
        save_problem_csv(result, path)
        assert path.exists()

    def test_csv_row_count(self, tmp_path):
        result = _make_scan_result()
        path = tmp_path / "out.csv"
        save_problem_csv(result, path)

        with open(path, newline="", encoding="utf-8-sig") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 2  # 1 expired + 1 expiring

    def test_csv_has_expected_columns(self, tmp_path):
        result = _make_scan_result()
        path = tmp_path / "out.csv"
        save_problem_csv(result, path)

        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            assert "hostname" in reader.fieldnames
            assert "days_left" in reader.fieldnames
            assert "status" in reader.fieldnames

    def test_creates_parent_dir(self, tmp_path):
        result = _make_scan_result()
        path = tmp_path / "nested" / "deep" / "out.csv"
        save_problem_csv(result, path)
        assert path.exists()


class TestSaveErrorsLog:
    def test_creates_file(self, tmp_path):
        result = _make_scan_result()
        path = tmp_path / "errors.log"
        save_errors_log(result, path)
        assert path.exists()

    def test_contains_ip(self, tmp_path):
        result = _make_scan_result()
        path = tmp_path / "errors.log"
        save_errors_log(result, path)
        content = path.read_text(encoding="utf-8")
        assert "192.168.1.50" in content
        assert "Access denied" in content


class TestSaveFullJson:
    def test_creates_valid_json(self, tmp_path):
        result = _make_scan_result()
        path = tmp_path / "data" / "latest.json"
        save_full_json(result, path)

        loaded = json.loads(path.read_text(encoding="utf-8"))
        assert loaded["summary"]["expired"] == 1
