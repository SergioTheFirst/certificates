"""Tests for net_cert_scanner.config."""

import pytest
from pathlib import Path

from net_cert_scanner.config import (
    Config,
    ConfigNotReadyError,
    load_or_create_config,
    NetworkConfig,
    CertificatesConfig,
    RotationConfig,
)


class TestConfigDefaults:
    def test_default_network_workers(self):
        cfg = Config()
        assert cfg.network.max_workers == 15

    def test_default_threshold_days(self):
        cfg = Config()
        assert cfg.certificates.expiration_threshold_days == 30

    def test_default_rotation(self):
        cfg = Config()
        assert cfg.rotation.max_reports == 30
        assert cfg.rotation.max_age_days == 90


class TestConfigValidation:
    def test_max_workers_zero_raises(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            NetworkConfig(max_workers=0)

    def test_threshold_negative_raises(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            CertificatesConfig(expiration_threshold_days=-1)

    def test_threshold_zero_is_ok(self):
        cfg = CertificatesConfig(expiration_threshold_days=0)
        assert cfg.expiration_threshold_days == 0


class TestLoadOrCreate:
    def test_creates_config_when_missing(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        with pytest.raises(ConfigNotReadyError):
            load_or_create_config(config_file)
        assert config_file.exists()

    def test_created_file_is_valid_yaml(self, tmp_path):
        import yaml
        config_file = tmp_path / "config.yaml"
        with pytest.raises(ConfigNotReadyError):
            load_or_create_config(config_file)

        with open(config_file) as f:
            data = yaml.safe_load(f)
        assert "credentials" in data
        assert "network" in data

    def test_loads_valid_config(self, tmp_path):
        import yaml
        config_file = tmp_path / "config.yaml"
        data = {
            "credentials": {"username": "admin", "password": "secret123"},
            "network": {"scan_range": "10.0.0.0/24", "max_workers": 10},
            "certificates": {"expiration_threshold_days": 14},
            "paths": {
                "reports_dir": "./reports",
                "html_path": "./out.html",
                "json_path": "./data/scan.json",
                "log_path": "./logs/app.log",
            },
            "rotation": {"max_reports": 5, "max_age_days": 30},
        }
        config_file.write_text(yaml.dump(data), encoding="utf-8")

        cfg = load_or_create_config(config_file)
        assert cfg.credentials.username == "admin"
        assert cfg.network.scan_range == "10.0.0.0/24"
        assert cfg.certificates.expiration_threshold_days == 14
        assert cfg.rotation.max_reports == 5

    def test_exits_when_password_is_placeholder(self, tmp_path):
        import yaml
        config_file = tmp_path / "config.yaml"
        data = {
            "credentials": {"username": "admin", "password": "CHANGE_ME"},
        }
        config_file.write_text(yaml.dump(data), encoding="utf-8")

        with pytest.raises(SystemExit) as exc_info:
            load_or_create_config(config_file)
        assert exc_info.value.code == 1

    def test_exits_when_password_empty(self, tmp_path):
        import yaml
        config_file = tmp_path / "config.yaml"
        data = {"credentials": {"username": "admin", "password": ""}}
        config_file.write_text(yaml.dump(data), encoding="utf-8")

        with pytest.raises(SystemExit):
            load_or_create_config(config_file)
