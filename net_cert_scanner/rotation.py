"""Report directory rotation for NetCertGuardian.

Keeps the reports/ directory from growing unbounded by removing old scan dirs.
Two policies (applied together if both configured):
  - max_reports: keep only the N most recent timestamped directories.
  - max_age_days: remove directories older than N days.
"""

from __future__ import annotations

import logging
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import List

log = logging.getLogger(__name__)

# Timestamp format used when creating run directories
RUN_DIR_STRFTIME = "%Y%m%d-%H%M%S"


def _sorted_run_dirs(reports_dir: Path) -> List[Path]:
    """Return scan run directories sorted oldest-first.

    Recognises directories whose names match YYYYMMDD-HHMMSS.
    Non-matching entries are skipped.
    """
    dirs: List[tuple[datetime, Path]] = []
    for entry in reports_dir.iterdir():
        if not entry.is_dir():
            continue
        try:
            ts = datetime.strptime(entry.name, RUN_DIR_STRFTIME)
            dirs.append((ts, entry))
        except ValueError:
            continue
    dirs.sort(key=lambda x: x[0])
    return [p for _, p in dirs]


def _remove_dir(path: Path) -> None:
    try:
        shutil.rmtree(path)
        log.info("Rotation: removed %s", path)
    except Exception as exc:
        log.warning("Rotation: could not remove %s: %s", path, exc)


def rotate(reports_dir: Path, max_reports: int = 0, max_age_days: int = 0) -> None:
    """Apply rotation policies to reports_dir.

    Args:
        reports_dir: Parent directory containing timestamped scan subdirs.
        max_reports: Keep at most this many dirs (0 = unlimited).
        max_age_days: Remove dirs older than this many days (0 = unlimited).
    """
    if not reports_dir.exists():
        return

    dirs = _sorted_run_dirs(reports_dir)

    if max_age_days > 0:
        cutoff = datetime.now() - timedelta(days=max_age_days)
        for path in list(dirs):
            try:
                ts = datetime.strptime(path.name, RUN_DIR_STRFTIME)
                if ts < cutoff:
                    _remove_dir(path)
                    dirs.remove(path)
            except ValueError:
                continue

    if max_reports > 0 and len(dirs) > max_reports:
        to_remove = dirs[: len(dirs) - max_reports]
        for path in to_remove:
            _remove_dir(path)

    remaining = len(_sorted_run_dirs(reports_dir))
    log.info("Rotation complete: %d report dir(s) retained", remaining)
