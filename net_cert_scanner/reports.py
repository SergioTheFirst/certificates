"""File report generation: CSV, JSON, error log, summary."""

from __future__ import annotations

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from .models import CertInfo, HostInfo, ScanResult

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# JSON serialization helpers
# ---------------------------------------------------------------------------

def _cert_to_dict(host: HostInfo, cert: CertInfo) -> Dict[str, Any]:
    return {
        "hostname": host.hostname,
        "ip": host.ip,
        "mac": host.mac,
        "subject": cert.subject,
        "issuer": cert.issuer,
        "not_after": cert.not_after.strftime("%Y-%m-%d"),
        "not_before": cert.not_before.strftime("%Y-%m-%d"),
        "days_left": cert.days_left,
        "status": cert.status,
        "thumbprint": cert.thumbprint,
    }


def _host_to_dict(host: HostInfo) -> Dict[str, Any]:
    return {
        "hostname": host.hostname,
        "ip": host.ip,
        "mac": host.mac,
        "total_certs": len(host.certs),
        "certs": [
            {
                "thumbprint": c.thumbprint,
                "subject": c.subject,
                "issuer": c.issuer,
                "not_after": c.not_after.strftime("%Y-%m-%d"),
                "not_before": c.not_before.strftime("%Y-%m-%d"),
                "days_left": c.days_left,
                "status": c.status,
            }
            for c in host.certs
        ],
    }


def build_scan_json(result: ScanResult) -> Dict[str, Any]:
    """Build the full JSON data structure used by HTML report and latest-scan.json."""
    return {
        "timestamp": result.timestamp.isoformat(),
        "scan_range": result.scan_range,
        "summary": {
            "total_discovered": result.total_discovered,
            "successful": result.successful,
            "failed": result.failed,
            "expired": result.expired_count,
            "expiring": result.expiring_count,
        },
        "problematic_certs": [
            _cert_to_dict(h, c) for h, c in result.all_problematic
        ],
        "hosts": [_host_to_dict(h) for h in result.hosts],
        "errors": [
            {
                "ip": e.ip,
                "hostname": e.hostname,
                "method": e.method,
                "reason": e.reason,
            }
            for e in result.errors
        ],
    }


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

def save_problem_csv(result: ScanResult, path: Path) -> None:
    """Write problematic certificates to a CSV file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "hostname", "ip", "mac", "subject", "issuer",
        "not_after", "days_left", "status", "thumbprint",
    ]
    rows = [_cert_to_dict(h, c) for h, c in result.all_problematic]

    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    log.info("CSV report: %d rows → %s", len(rows), path)


def save_errors_log(result: ScanResult, path: Path) -> None:
    """Write connection errors to a plain-text log file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(
            f"# Scan errors — {result.timestamp.isoformat()}\n"
            f"# Total: {result.failed} host(s) failed\n\n"
        )
        for err in result.errors:
            fh.write(
                f"{err.ip:<18} method={err.method:<10} reason={err.reason}\n"
            )
    log.info("Error log: %d entries → %s", len(result.errors), path)


def save_summary_json(result: ScanResult, path: Path) -> None:
    """Write a brief JSON summary of the scan."""
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "timestamp": result.timestamp.isoformat(),
        "scan_range": result.scan_range,
        "total_discovered": result.total_discovered,
        "successful": result.successful,
        "failed": result.failed,
        "total_certs": sum(len(h.certs) for h in result.hosts),
        "expired": result.expired_count,
        "expiring": result.expiring_count,
    }
    path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    log.info("Summary JSON → %s", path)


def save_full_json(result: ScanResult, path: Path) -> None:
    """Write the full scan JSON (used by HTML and latest-scan.json)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = build_scan_json(result)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    log.info("Full JSON (%d hosts, %d errors) → %s", result.successful, result.failed, path)


def save_all_reports(result: ScanResult, run_dir: Path, latest_json_path: Path) -> None:
    """Save all file reports for one scan run.

    Args:
        result: Completed and analysed ScanResult.
        run_dir: Timestamped directory for this run's archived reports.
        latest_json_path: Path to overwrite with latest-scan.json every run.
    """
    run_dir.mkdir(parents=True, exist_ok=True)

    save_problem_csv(result, run_dir / "problem_certs.csv")
    save_errors_log(result, run_dir / "errors.log")
    save_summary_json(result, run_dir / "summary.json")
    save_full_json(result, run_dir / "full_data.json")

    # Always update the "latest" JSON so the HTML generator can use it
    save_full_json(result, latest_json_path)
