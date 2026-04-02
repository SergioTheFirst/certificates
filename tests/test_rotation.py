"""Tests for net_cert_scanner.rotation."""

import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from net_cert_scanner.rotation import RUN_DIR_STRFTIME, _sorted_run_dirs, rotate


def _make_run_dir(base: Path, dt: datetime) -> Path:
    d = base / dt.strftime(RUN_DIR_STRFTIME)
    d.mkdir(parents=True)
    (d / "summary.json").write_text("{}", encoding="utf-8")
    return d


class TestSortedRunDirs:
    def test_returns_sorted_oldest_first(self, tmp_path):
        now = datetime(2025, 4, 2, 12, 0, 0)
        d1 = _make_run_dir(tmp_path, now - timedelta(days=2))
        d2 = _make_run_dir(tmp_path, now - timedelta(days=1))
        d3 = _make_run_dir(tmp_path, now)

        result = _sorted_run_dirs(tmp_path)
        assert result == [d1, d2, d3]

    def test_ignores_non_matching_dirs(self, tmp_path):
        _make_run_dir(tmp_path, datetime(2025, 4, 1))
        (tmp_path / "random-dir").mkdir()
        (tmp_path / "also_not_matching").mkdir()

        result = _sorted_run_dirs(tmp_path)
        assert len(result) == 1

    def test_empty_directory(self, tmp_path):
        assert _sorted_run_dirs(tmp_path) == []


class TestRotate:
    def test_respects_max_reports(self, tmp_path):
        now = datetime(2025, 4, 2)
        for i in range(10):
            _make_run_dir(tmp_path, now - timedelta(days=i))

        rotate(tmp_path, max_reports=3, max_age_days=0)

        remaining = _sorted_run_dirs(tmp_path)
        assert len(remaining) == 3

    def test_keeps_newest_on_max_reports(self, tmp_path):
        base = datetime(2025, 4, 2)
        dirs = [_make_run_dir(tmp_path, base - timedelta(days=i)) for i in range(5)]
        # dirs[0] is newest (base), dirs[4] is oldest

        rotate(tmp_path, max_reports=2, max_age_days=0)

        remaining = _sorted_run_dirs(tmp_path)
        assert len(remaining) == 2
        # The two newest should survive
        assert dirs[0] in remaining
        assert dirs[1] in remaining

    def test_removes_old_by_age(self, tmp_path):
        base = datetime.now()
        old1 = _make_run_dir(tmp_path, base - timedelta(days=100))
        old2 = _make_run_dir(tmp_path, base - timedelta(days=91))
        new1 = _make_run_dir(tmp_path, base - timedelta(days=5))

        rotate(tmp_path, max_reports=0, max_age_days=90)

        remaining = _sorted_run_dirs(tmp_path)
        assert new1 in remaining
        assert old1 not in remaining
        assert old2 not in remaining

    def test_no_op_when_under_limit(self, tmp_path):
        now = datetime(2025, 4, 2)
        for i in range(3):
            _make_run_dir(tmp_path, now - timedelta(days=i))

        rotate(tmp_path, max_reports=10, max_age_days=0)

        assert len(_sorted_run_dirs(tmp_path)) == 3

    def test_no_crash_on_missing_dir(self, tmp_path):
        non_existent = tmp_path / "does_not_exist"
        # Should not raise
        rotate(non_existent, max_reports=5, max_age_days=30)
