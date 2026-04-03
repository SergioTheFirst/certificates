"""NetCertGuardian — entry point.

Run with:  python -m net_cert_scanner

Exit codes:
  0 — success (including first-run config creation)
  1 — critical error (invalid config, no network, unhandled exception)
"""

from __future__ import annotations

import logging
import sys
import traceback
from datetime import datetime
from pathlib import Path

from .config import ConfigNotReadyError, load_or_create_config
from .analyzer import analyze
from .collector import collect_all
from .discovery import discover_hosts, get_local_subnet
from .html_report import generate_html
from .reports import build_scan_json, save_all_reports
from .rotation import rotate


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(log_path: str) -> None:
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fmt = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.FileHandler(path, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


# ---------------------------------------------------------------------------
# Impacket diagnostics
# ---------------------------------------------------------------------------

def _check_impacket(log: logging.Logger) -> None:
    """Log impacket version and verify required modules are importable."""
    try:
        import impacket
        ver = getattr(impacket, "version", getattr(impacket, "__version__", "unknown"))
        log.info("impacket version: %s", ver)
    except ImportError:
        log.error("impacket is NOT installed. Run: pip install impacket")
        raise SystemExit(1)

    modules = {
        "SMBConnection": "impacket.smbconnection",
        "DCOMConnection": "impacket.dcerpc.v5.dcomrt",
        "scmr (smbexec)": "impacket.dcerpc.v5.scmr",
    }
    for label, mod_path in modules.items():
        try:
            __import__(mod_path)
            log.info("  %-20s OK (%s)", label, mod_path)
        except ImportError as exc:
            log.warning("  %-20s MISSING (%s) — %s", label, mod_path, exc)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    # ------------------------------------------------------------------
    # 1. Config
    # ------------------------------------------------------------------
    try:
        cfg = load_or_create_config()
    except ConfigNotReadyError:
        # Config template just created; tell user and exit cleanly.
        return 0
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 1

    _setup_logging(cfg.paths.log_path)
    log = logging.getLogger(__name__)
    log.info("=" * 60)
    log.info("NetCertGuardian started")

    # Pre-check impacket availability
    _check_impacket(log)

    # ------------------------------------------------------------------
    # 2. Determine scan range
    # ------------------------------------------------------------------
    try:
        if cfg.network.scan_range:
            scan_range = cfg.network.scan_range
            log.info("Using configured scan range: %s", scan_range)
        else:
            scan_range = get_local_subnet()
    except RuntimeError as exc:
        log.error("Cannot determine network range: %s", exc)
        return 1

    # ------------------------------------------------------------------
    # 3. Discovery — TCP:445
    # ------------------------------------------------------------------
    try:
        live_ips = discover_hosts(
            scan_range=scan_range,
            exclude_ips=cfg.network.exclude_ips,
            timeout=float(cfg.network.discovery_timeout),
            max_workers=50,
        )
    except Exception as exc:
        log.error("Discovery failed: %s", exc)
        return 1

    if not live_ips:
        log.warning("No hosts found with port 445 open in %s", scan_range)
        # Still generate an empty report so the HTML reflects the scan ran
        live_ips = []

    # ------------------------------------------------------------------
    # 4. Collection
    # ------------------------------------------------------------------
    result = collect_all(
        live_ips=live_ips,
        username=cfg.credentials.username,
        password=cfg.credentials.password,
        max_workers=cfg.network.max_workers,
        timeout=cfg.network.collection_timeout,
    )
    result.scan_range = scan_range

    # ------------------------------------------------------------------
    # 5. Analysis
    # ------------------------------------------------------------------
    analyze(result, cfg.certificates.expiration_threshold_days)

    # ------------------------------------------------------------------
    # 6. Reports
    # ------------------------------------------------------------------
    run_ts = result.timestamp.strftime("%Y%m%d-%H%M%S")
    reports_dir = Path(cfg.paths.reports_dir)
    run_dir = reports_dir / run_ts
    latest_json = Path(cfg.paths.json_path)

    try:
        save_all_reports(result, run_dir, latest_json)
    except Exception as exc:
        log.error("Failed to save reports: %s", exc, exc_info=True)
        return 1

    # ------------------------------------------------------------------
    # 7. HTML
    # ------------------------------------------------------------------
    try:
        scan_data = build_scan_json(result)
        generate_html(scan_data, Path(cfg.paths.html_path))
    except Exception as exc:
        log.error("Failed to generate HTML: %s", exc, exc_info=True)
        return 1

    # ------------------------------------------------------------------
    # 8. Rotation
    # ------------------------------------------------------------------
    try:
        rotate(
            reports_dir=reports_dir,
            max_reports=cfg.rotation.max_reports,
            max_age_days=cfg.rotation.max_age_days,
        )
    except Exception as exc:
        # Rotation failure is non-critical
        log.warning("Rotation error (non-critical): %s", exc)

    # ------------------------------------------------------------------
    # 9. Summary to stdout
    # ------------------------------------------------------------------
    log.info(
        "DONE — hosts: %d discovered, %d ok, %d failed | "
        "certs: %d expired, %d expiring",
        result.total_discovered,
        result.successful,
        result.failed,
        result.expired_count,
        result.expiring_count,
    )
    print(f"\n✅  Report ready: {Path(cfg.paths.html_path).resolve()}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(1)
