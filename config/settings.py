"""
Settings loader — merges .env file and config.yaml into a single typed config object.
Usage anywhere in the project:
    from config.settings import get_settings
    settings = get_settings()
    print(settings.api_port)
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

import yaml
from pydantic_settings import BaseSettings
from pydantic import Field


# ---------------------------------------------------------------------------
# Locate project root (directory containing config.yaml)
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_yaml_config() -> dict:
    """Load config.yaml and return as a flat-ish dict."""
    config_path = PROJECT_ROOT / "config.yaml"
    if not config_path.exists():
        return {}
    with open(config_path, "r") as f:
        raw = yaml.safe_load(f) or {}

    # Flatten one level so pydantic can pick up nested keys
    flat = {}
    for section, values in raw.items():
        if isinstance(values, dict):
            for key, val in values.items():
                flat[f"{section}_{key}"] if False else flat.update({key: val})
        else:
            flat[section] = values
    return flat


# ---------------------------------------------------------------------------
# Settings model
# ---------------------------------------------------------------------------
class Settings(BaseSettings):
    """Unified app settings — .env values override config.yaml defaults."""

    # App
    app_name: str = "ASTRA"
    app_env: str = "production"
    version: str = "0.1.0"
    debug: bool = False

    # Server
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    dashboard_port: int = 8050
    reload: bool = False

    # Database
    database_url: str = "sqlite+aiosqlite:///./astra.db"
    db_echo: bool = False

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    redis_enabled: bool = False

    # Simulation
    default_difficulty: str = "medium"
    log_stream_interval_ms: int = 500
    noise_ratio: float = 0.6
    max_session_duration_minutes: int = 60

    # Scoring weights — must sum to 1.0
    weight_detection_rate: float = 0.25
    weight_mttd: float = 0.20
    weight_fp_rate: float = 0.10
    weight_containment: float = 0.10
    weight_report_quality: float = 0.15
    weight_coverage: float = 0.20

    # MITRE
    mitre_attack_version: str = "15.1"
    mitre_matrix: str = "enterprise"

    # Reports
    report_output_dir: str = "reports/output"
    report_templates_dir: str = "reports/templates"

    model_config = {
        "env_file": str(PROJECT_ROOT / ".env"),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------
@lru_cache()
def get_settings() -> Settings:
    """Return a cached Settings instance. Call once at startup."""
    yaml_defaults = _load_yaml_config()
    return Settings(**{k: v for k, v in yaml_defaults.items() if v is not None})
