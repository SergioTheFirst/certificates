"""Network host discovery for NetCertGuardian.

Primary method: TCP connect to port 445 (SMB).
Rationale: Windows Firewall blocks ICMP by default on Win10/11 workstations,
but SMB port 445 must be open for the collection step to work anyway.
If 445 is closed, WMI collection will also fail — no point including the host.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

import psutil

log = logging.getLogger(__name__)


def get_local_subnet() -> str:
    """Detect the local network subnet via psutil interface addresses.

    Returns the first private IPv4 CIDR found on a non-loopback interface.
    Raises RuntimeError if no suitable interface is found.
    """
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            # AF_INET == 2
            if addr.family != socket.AF_INET:
                continue
            if addr.address.startswith("127."):
                continue
            if not addr.netmask:
                continue
            try:
                net = ipaddress.IPv4Network(
                    f"{addr.address}/{addr.netmask}", strict=False
                )
                if net.is_private:
                    log.info("Auto-detected subnet %s on interface %s", net, iface)
                    return str(net)
            except ValueError:
                continue
    raise RuntimeError(
        "Could not auto-detect local subnet. "
        "Set network.scan_range in config.yaml."
    )


def _tcp_reachable(ip: str, port: int = 445, timeout: float = 2.0) -> bool:
    """Return True if TCP connection to ip:port succeeds within timeout."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def discover_hosts(
    scan_range: str,
    exclude_ips: List[str],
    timeout: float = 2.0,
    max_workers: int = 50,
) -> List[str]:
    """Return list of IPs in scan_range that have port 445 open.

    Args:
        scan_range: CIDR string, e.g. "192.168.1.0/24".
        exclude_ips: IPs to skip unconditionally.
        timeout: TCP connect timeout per host (seconds).
        max_workers: parallel threads for scanning.

    Returns:
        Sorted list of reachable IP strings.
    """
    try:
        network = ipaddress.IPv4Network(scan_range, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid scan_range '{scan_range}': {exc}") from exc

    candidates = [
        str(ip) for ip in network.hosts() if str(ip) not in exclude_ips
    ]
    log.info(
        "Scanning %d addresses in %s (excluding %d)",
        len(candidates),
        scan_range,
        len(exclude_ips),
    )

    reachable: List[str] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_ip = {
            pool.submit(_tcp_reachable, ip, 445, timeout): ip
            for ip in candidates
        }
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    reachable.append(ip)
            except Exception as exc:
                log.debug("Discovery check failed for %s: %s", ip, exc)

    reachable.sort(key=lambda x: ipaddress.IPv4Address(x))
    log.info("Discovery complete: %d/%d hosts reachable on port 445", len(reachable), len(candidates))
    return reachable
