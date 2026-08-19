"""Async-safe token bucket rate limiter for ShadowGate Proxy."""

import asyncio
import time
from typing import Dict

from shadowgate.config import Config


class TokenBucket:
    """An async-safe token bucket for rate limiting."""

    def __init__(self, max_tokens: float, refill_rate: float):
        self.max_tokens = max_tokens
        self.tokens = max_tokens
        self.refill_rate = refill_rate
        self.last_refill = time.monotonic()  # monotonic avoids Windows clock drift
        self._lock = asyncio.Lock()

    async def consume(self) -> bool:
        """Try to consume a token. Returns True if allowed."""
        async with self._lock:
            self._refill()
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_refill
        if elapsed > 0:
            self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now

    @property
    def info(self) -> dict:
        return {
            "tokens": round(self.tokens, 2),
            "max_tokens": self.max_tokens,
            "refill_rate": self.refill_rate,
        }


class RateLimiter:
    """Async rate limiter managing per-identifier token buckets."""

    def __init__(self, config: Config):
        self.config = config
        self.rate_limit_enabled = self.config.get(
            "proxy", "rate_limit", "enabled", default=True
        )
        self.default_max_tokens = float(
            self.config.get("proxy", "rate_limit", "burst_size", default=10)
        )
        rpm = float(
            self.config.get("proxy", "rate_limit", "requests_per_minute", default=60)
        )
        self.default_refill_rate = rpm / 60.0

        self._buckets: Dict[str, TokenBucket] = {}
        self._buckets_lock = asyncio.Lock()

        # Cleanup stale buckets periodically
        self._cleanup_interval = 300  # seconds
        self._max_idle = 600  # remove buckets idle for 10 minutes

    def is_allowed(self, identifier: str) -> bool:
        """Synchronous check — creates bucket if needed, consumes token.
        
        For backwards compatibility. Prefer `async_is_allowed()` in async code.
        """
        if not self.rate_limit_enabled:
            return True

        if identifier not in self._buckets:
            self._buckets[identifier] = TokenBucket(
                self.default_max_tokens, self.default_refill_rate
            )
        bucket = self._buckets[identifier]

        # Synchronous refill + consume
        bucket._refill()
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return True
        return False

    async def async_is_allowed(self, identifier: str) -> bool:
        """Async-safe rate limit check."""
        if not self.rate_limit_enabled:
            return True

        async with self._buckets_lock:
            if identifier not in self._buckets:
                self._buckets[identifier] = TokenBucket(
                    self.default_max_tokens, self.default_refill_rate
                )
            bucket = self._buckets[identifier]

        return await bucket.consume()

    async def cleanup_stale_buckets(self) -> int:
        """Remove buckets that haven't been used recently."""
        now = time.monotonic()
        removed = 0
        async with self._buckets_lock:
            stale_keys = [
                k for k, b in self._buckets.items()
                if now - b.last_refill > self._max_idle
            ]
            for key in stale_keys:
                del self._buckets[key]
                removed += 1
        return removed

    def get_stats(self) -> dict:
        """Return current rate limit statistics."""
        return {
            identifier: bucket.info
            for identifier, bucket in self._buckets.items()
        }
