"""Tests for ShadowGate proxy components."""

import pytest
from unittest.mock import MagicMock
from shadowgate.config import Config
from shadowgate.proxy.auth import ProxyAuthenticator
from shadowgate.proxy.rate_limiter import RateLimiter
from shadowgate.proxy.acl import AccessController


class TestProxyAuth:
    """Test proxy authentication."""

    def setup_method(self):
        self.config = Config()

    def test_authenticator_init(self):
        auth = ProxyAuthenticator(self.config)
        assert auth is not None

    def test_valid_api_key(self):
        auth = ProxyAuthenticator(self.config)
        api_keys = self.config.get("proxy", "auth", "api_keys", default=[])
        if api_keys:
            result = auth._check_api_key(api_keys[0])
            assert result is not None


class TestRateLimiter:
    """Test rate limiting."""

    def setup_method(self):
        self.config = Config()

    def test_allows_first_request(self):
        limiter = RateLimiter(self.config)
        assert limiter.is_allowed("test-ip") is True

    def test_rate_limit_exceeded(self):
        limiter = RateLimiter(self.config)
        # Exhaust all tokens
        burst = self.config.get("proxy", "rate_limit", "burst_size", default=10)
        for _ in range(burst + 1):
            limiter.is_allowed("flood-ip")
        # Next request should be denied
        assert limiter.is_allowed("flood-ip") is False


class TestAccessControl:
    """Test IP access control."""

    def setup_method(self):
        self.config = Config()

    def test_default_allows_all(self):
        acl = AccessController(self.config)
        allowed, reason = acl.is_allowed("192.168.1.1")
        assert allowed is True

    def test_blacklist(self):
        acl = AccessController(self.config)
        acl.add_to_blacklist("10.0.0.1")
        allowed, reason = acl.is_allowed("10.0.0.1")
        assert allowed is False
        assert "blacklist" in reason.lower()

    def test_remove_from_blacklist(self):
        acl = AccessController(self.config)
        acl.add_to_blacklist("10.0.0.2")
        acl.remove_from_blacklist("10.0.0.2")
        allowed, _ = acl.is_allowed("10.0.0.2")
        assert allowed is True
