"""Certificate analysis: classify certs as expired, expiring, or ok."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List

from .models import CertInfo, HostInfo, ScanResult

log = logging.getLogger(__name__)


def _utc_now() -> datetime:
    """Return current UTC time (naive, for comparison with cert dates)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def classify_cert(cert: CertInfo, threshold_days: int, now: datetime) -> str:
    """Return status string for a single certificate.

    Args:
        cert: The certificate to classify.
        threshold_days: Days ahead to consider "expiring".
        now: Current datetime (naive UTC).

    Returns:
        "expired" | "expiring" | "ok"
    """
    if cert.days_left < 0:
        return "expired"
    if cert.days_left <= threshold_days:
        return "expiring"
    return "ok"


def analyze(result: ScanResult, threshold_days: int) -> None:
    """Classify all certificates in-place within result.hosts.

    Sets cert.status on every CertInfo to "expired", "expiring", or "ok".
    Logs a summary per host.
    """
    now = _utc_now()
    total_certs = 0
    total_problematic = 0

    for host in result.hosts:
        host_problematic = 0
        for cert in host.certs:
            cert.status = classify_cert(cert, threshold_days, now)
            total_certs += 1
            if cert.status != "ok":
                host_problematic += 1
                total_problematic += 1

        if host_problematic:
            log.info(
                "Host %s (%s): %d problematic cert(s) of %d",
                host.hostname,
                host.ip,
                host_problematic,
                len(host.certs),
            )

    log.info(
        "Analysis done: %d total certs, %d problematic (%d expired, %d expiring)",
        total_certs,
        total_problematic,
        result.expired_count,
        result.expiring_count,
    )
