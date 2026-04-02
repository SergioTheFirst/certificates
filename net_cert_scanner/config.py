"""Configuration loading and validation for NetCertGuardian."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

CONFIG_PATH = Path("config.yaml")


class CredentialsConfig(BaseModel):
    username: str = "DOMAIN\\\\Administrator"
    password: str = "CHANGE_ME"


class NetworkConfig(BaseModel):
    scan_range: str = ""
    exclude_ips: List[str] = Field(default_factory=list)
    max_workers: int = 15
    discovery_timeout: int = 2
    collection_timeout: int = 30

    @field_validator("max_workers")
    @classmethod
    def workers_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("max_workers must be >= 1")
        return v


class CertificatesConfig(BaseModel):
    store: str = "LocalMachine\\\\My"
    expiration_threshold_days: int = 30

    @field_validator("expiration_threshold_days")
    @classmethod
    def threshold_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("expiration_threshold_days must be >= 0")
        return v


class PathsConfig(BaseModel):
    reports_dir: str = "./reports"
    html_path: str = "./cert-status.html"
    json_path: str = "./data/latest-scan.json"
    log_path: str = "./logs/app.log"


class RotationConfig(BaseModel):
    max_reports: int = 30
    max_age_days: int = 90


class Config(BaseModel):
    credentials: CredentialsConfig = Field(default_factory=CredentialsConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    certificates: CertificatesConfig = Field(default_factory=CertificatesConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)
    rotation: RotationConfig = Field(default_factory=RotationConfig)


class ConfigNotReadyError(Exception):
    """Raised when config was just created and user needs to fill it in."""


def _default_config_yaml() -> str:
    return """\
credentials:
  username: "DOMAIN\\\\Administrator"
  password: "CHANGE_ME"

network:
  scan_range: ""
  exclude_ips: []
  max_workers: 15
  discovery_timeout: 2
  collection_timeout: 30

certificates:
  store: "LocalMachine\\\\My"
  expiration_threshold_days: 30

paths:
  reports_dir: "./reports"
  html_path: "./cert-status.html"
  json_path: "./data/latest-scan.json"
  log_path: "./logs/app.log"

rotation:
  max_reports: 30
  max_age_days: 90
"""


def load_or_create_config(config_path: Optional[Path] = None) -> Config:
    """Load config.yaml or create a default template and raise ConfigNotReadyError.

    Raises:
        ConfigNotReadyError: if config was just created (user must edit it).
        SystemExit: on validation error.
    """
    path = config_path or CONFIG_PATH

    if not path.exists():
        path.write_text(_default_config_yaml(), encoding="utf-8")
        # Restrict file permissions on creation (best effort, Windows may ignore)
        try:
            import stat
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass
        print(
            f"[NetCertGuardian] Config created: {path}\n"
            "  Edit credentials.username and credentials.password, then re-run.",
            file=sys.stderr,
        )
        raise ConfigNotReadyError(f"Config created at {path}. Please edit and re-run.")

    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    try:
        cfg = Config.model_validate(raw or {})
    except Exception as exc:
        print(f"[NetCertGuardian] Invalid config: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    if cfg.credentials.password in ("CHANGE_ME", "", None):
        print(
            "[NetCertGuardian] credentials.password is not set in config.yaml.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    return cfg
