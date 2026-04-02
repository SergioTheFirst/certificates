"""Data models for NetCertGuardian."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List


@dataclass
class CertInfo:
    """A single certificate from a remote Windows certificate store."""

    thumbprint: str
    subject: str
    issuer: str
    not_after: datetime
    not_before: datetime
    days_left: int
    status: str = ""  # filled by analyzer: "ok" | "expiring" | "expired"


@dataclass
class HostInfo:
    """Successfully scanned host with its certificates."""

    ip: str
    hostname: str = ""
    mac: str = ""
    certs: List[CertInfo] = field(default_factory=list)

    @property
    def problematic_certs(self) -> List[CertInfo]:
        return [c for c in self.certs if c.status in ("expiring", "expired")]


@dataclass
class ScanError:
    """Host that could not be reached or authenticated."""

    ip: str
    hostname: str = ""
    method: str = ""
    reason: str = ""


@dataclass
class ScanResult:
    """Aggregated result of a full scan cycle."""

    timestamp: datetime
    scan_range: str = ""
    hosts: List[HostInfo] = field(default_factory=list)
    errors: List[ScanError] = field(default_factory=list)

    @property
    def total_discovered(self) -> int:
        return len(self.hosts) + len(self.errors)

    @property
    def successful(self) -> int:
        return len(self.hosts)

    @property
    def failed(self) -> int:
        return len(self.errors)

    @property
    def all_problematic(self) -> List[tuple[HostInfo, CertInfo]]:
        result: List[tuple[HostInfo, CertInfo]] = []
        for host in self.hosts:
            for cert in host.certs:
                if cert.status in ("expiring", "expired"):
                    result.append((host, cert))
        return result

    @property
    def expired_count(self) -> int:
        return sum(1 for _, c in self.all_problematic if c.status == "expired")

    @property
    def expiring_count(self) -> int:
        return sum(1 for _, c in self.all_problematic if c.status == "expiring")
