"""Token bucket rate limiter for ShadowGate Proxy."""

import time
import threading
from typing import Dict

from shadowgate.config import Config


class TokenBucket:
    """A token bucket for rate limiting."""

    def __init__(self, max_tokens: float, refill_rate: float):
        self.max_tokens = max_tokens
        self.tokens = max_tokens
        self.refill_rate = refill_rate
        self.last_refill = time.time()
        self.lock = threading.Lock()


class RateLimiter:
    """Rate limiter managing token buckets for different identifiers."""

    def __init__(self, config: Config):
        self.config = config
        self.rate_limit_enabled = self.config.get(
            "proxy", "rate_limit", "enabled", default=True
        )
        # burst_size = max tokens in the bucket
        self.default_max_tokens = float(
            self.config.get("proxy", "rate_limit", "burst_size", default=10)
        )
        # requests_per_minute -> tokens per second
        rpm = float(
            self.config.get("proxy", "rate_limit", "requests_per_minute", default=60)
        )
        self.default_refill_rate = rpm / 60.0

        self.buckets: Dict[str, TokenBucket] = {}
        self.lock = threading.Lock()

    def is_allowed(self, identifier: str) -> bool:
        """Check if a request from this identifier is allowed."""
        if not self.rate_limit_enabled:
            return True

        with self.lock:
            if identifier not in self.buckets:
                self.buckets[identifier] = TokenBucket(
                    self.default_max_tokens,
                    self.default_refill_rate,
                )
            bucket = self.buckets[identifier]

        with bucket.lock:
            self._refill(bucket)
            if bucket.tokens >= 1:
                bucket.tokens -= 1
                return True
            return False

    def _refill(self, bucket: TokenBucket) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - bucket.last_refill

        if elapsed > 0:
            tokens_to_add = elapsed * bucket.refill_rate
            bucket.tokens = min(bucket.max_tokens, bucket.tokens + tokens_to_add)
            bucket.last_refill = now

    def get_stats(self) -> dict:
        """Return current rate limit statistics."""
        stats = {}
        with self.lock:
            for identifier, bucket in self.buckets.items():
                with bucket.lock:
                    self._refill(bucket)
                    stats[identifier] = {
                        "tokens": bucket.tokens,
                        "max_tokens": bucket.max_tokens,
                        "refill_rate": bucket.refill_rate,
                    }
        return stats
