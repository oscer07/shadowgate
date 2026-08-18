"""Configuration management for ShadowGate.

Loads configuration from YAML files and environment variables.
Environment variables override YAML values using the SHADOWGATE_ prefix.
"""

import os
from pathlib import Path
from typing import Any, Optional

import yaml


DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "default.yaml"


class Config:
    """Hierarchical configuration with YAML + environment variable support."""

    def __init__(self, config_path: Optional[str] = None):
        self._data: dict = {}
        self._load_defaults()
        if config_path:
            self._load_file(config_path)
        self._apply_env_overrides()

    def _load_defaults(self) -> None:
        """Load default configuration from bundled YAML."""
        if DEFAULT_CONFIG_PATH.exists():
            with open(DEFAULT_CONFIG_PATH, "r") as f:
                self._data = yaml.safe_load(f) or {}

    def _load_file(self, path: str) -> None:
        """Merge a user-provided config file over defaults."""
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        with open(config_path, "r") as f:
            user_config = yaml.safe_load(f) or {}
        self._data = self._deep_merge(self._data, user_config)

    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides.
        
        Maps SHADOWGATE_SECTION_KEY=value to config[section][key] = value.
        Supports nested keys with double underscores:
        SHADOWGATE_PROXY__AUTH__ENABLED=false -> config[proxy][auth][enabled] = false
        """
        prefix = "SHADOWGATE_"
        for key, value in os.environ.items():
            if not key.startswith(prefix):
                continue
            parts = key[len(prefix):].lower().split("__")
            # Navigate to the right nesting level
            target = self._data
            for part in parts[:-1]:
                if part not in target:
                    target[part] = {}
                target = target[part]
            # Type coercion
            target[parts[-1]] = self._coerce_type(value)

    @staticmethod
    def _coerce_type(value: str) -> Any:
        """Coerce string env var values to appropriate Python types."""
        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0"):
            return False
        try:
            return int(value)
        except ValueError:
            pass
        try:
            return float(value)
        except ValueError:
            pass
        return value

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        """Deep merge two dictionaries, with override taking precedence."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = Config._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def get(self, *keys: str, default: Any = None) -> Any:
        """Get a nested config value by dotted key path.
        
        Usage:
            config.get("proxy", "port")  # -> 8080
            config.get("proxy", "auth", "enabled")  # -> True
        """
        current = self._data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

    @property
    def proxy(self) -> dict:
        return self._data.get("proxy", {})

    @property
    def honeypot(self) -> dict:
        return self._data.get("honeypot", {})

    @property
    def dashboard(self) -> dict:
        return self._data.get("dashboard", {})

    @property
    def logging_config(self) -> dict:
        return self._data.get("logging", {})

    @property
    def alerts(self) -> dict:
        return self._data.get("alerts", {})

    def __repr__(self) -> str:
        return f"Config(sections={list(self._data.keys())})"
