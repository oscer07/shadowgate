"""Tests for ShadowGate configuration system."""

import os
import tempfile
import pytest
from shadowgate.config import Config


class TestConfig:
    """Test configuration loading and merging."""

    def test_load_defaults(self):
        """Default config should load successfully."""
        config = Config()
        assert config.proxy is not None
        assert config.get("proxy", "port") == 8080
        assert config.get("proxy", "auth", "enabled") is True

    def test_custom_config_override(self):
        """Custom config should override defaults."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("proxy:\n  port: 9999\n")
            f.flush()
            config = Config(f.name)
            assert config.get("proxy", "port") == 9999
            # Default values should still be present
            assert config.get("proxy", "auth", "enabled") is True
        os.unlink(f.name)

    def test_env_override(self):
        """Environment variables should override config values."""
        os.environ["SHADOWGATE_PROXY__PORT"] = "7777"
        try:
            config = Config()
            assert config.get("proxy", "port") == 7777
        finally:
            del os.environ["SHADOWGATE_PROXY__PORT"]

    def test_missing_config_file(self):
        """Should raise FileNotFoundError for missing config."""
        with pytest.raises(FileNotFoundError):
            Config("/nonexistent/config.yaml")

    def test_get_default_value(self):
        """Should return default for missing keys."""
        config = Config()
        assert config.get("nonexistent", "key", default="fallback") == "fallback"

    def test_type_coercion(self):
        """Environment variable types should be coerced correctly."""
        os.environ["SHADOWGATE_TEST__BOOL_TRUE"] = "true"
        os.environ["SHADOWGATE_TEST__BOOL_FALSE"] = "false"
        os.environ["SHADOWGATE_TEST__INT_VAL"] = "42"
        os.environ["SHADOWGATE_TEST__FLOAT_VAL"] = "3.14"
        os.environ["SHADOWGATE_TEST__STR_VAL"] = "hello"
        try:
            config = Config()
            assert config.get("test", "bool_true") is True
            assert config.get("test", "bool_false") is False
            assert config.get("test", "int_val") == 42
            assert config.get("test", "float_val") == 3.14
            assert config.get("test", "str_val") == "hello"
        finally:
            for k in ["SHADOWGATE_TEST__BOOL_TRUE", "SHADOWGATE_TEST__BOOL_FALSE",
                      "SHADOWGATE_TEST__INT_VAL", "SHADOWGATE_TEST__FLOAT_VAL",
                      "SHADOWGATE_TEST__STR_VAL"]:
                del os.environ[k]
