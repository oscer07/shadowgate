"""Structured JSON logging and in-memory event store for ShadowGate."""

import json
import logging
import os
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional


class JSONFormatter(logging.Formatter):
    """Formats log records as structured JSON."""

    # Fields from LogRecord that we skip (internal Python logging fields)
    _SKIP_FIELDS = frozenset({
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "module", "msecs",
        "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "thread", "threadName",
        "message", "taskName",
    })

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add extra attributes
        for key, value in record.__dict__.items():
            if key not in self._SKIP_FIELDS:
                try:
                    json.dumps(value)  # ensure serializable
                    log_data[key] = value
                except (TypeError, ValueError):
                    log_data[key] = str(value)

        return json.dumps(log_data, default=str)


class EventStore:
    """Thread-safe in-memory event store for the dashboard.
    
    Uses a bounded deque to prevent memory leaks during long-running operation.
    Maintains running counters for O(1) stats lookups.
    """

    def __init__(self, maxlen: int = 10000):
        self.events: deque = deque(maxlen=maxlen)
        self._lock = threading.Lock()

        # Running counters for fast stats (no full scan needed)
        self._protocol_counts: Counter = Counter()
        self._event_type_counts: Counter = Counter()
        self._ip_counts: Counter = Counter()
        self._total_events: int = 0
        self._credentials: deque = deque(maxlen=200)  # last 200 credential captures

    def add_event(self, event: Dict[str, Any]) -> None:
        """Add an event with auto-timestamp. Updates running counters."""
        if "timestamp" not in event:
            event["timestamp"] = datetime.now(timezone.utc).isoformat()

        with self._lock:
            # If deque is full, the oldest event is dropped automatically
            # We don't decrement counters for dropped events (counters are cumulative)
            self.events.appendleft(event)
            self._total_events += 1

            # Update counters
            proto = event.get("protocol", "unknown")
            self._protocol_counts[proto] += 1

            etype = event.get("event_type", "unknown")
            self._event_type_counts[etype] += 1

            src_ip = event.get("source_ip")
            if src_ip:
                self._ip_counts[src_ip] += 1

            # Track credentials
            if "login_attempt" in etype or "password" in event:
                cred = {
                    "timestamp": event["timestamp"],
                    "protocol": proto,
                    "source_ip": src_ip or "unknown",
                    "username": event.get("username", ""),
                    "password": event.get("password", ""),
                    "target": event.get("target", ""),
                }
                self._credentials.appendleft(cred)

    def get_events(
        self,
        limit: int = 100,
        protocol: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve events with optional filters."""
        with self._lock:
            results = []
            for event in self.events:
                if protocol and event.get("protocol") != protocol:
                    continue
                if event_type and event.get("event_type") != event_type:
                    continue
                results.append(event)
                if len(results) >= limit:
                    break
            return results

    def get_credentials(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recently captured credentials."""
        with self._lock:
            return list(self._credentials)[:limit]

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate statistics. O(1) for most fields."""
        with self._lock:
            return {
                "total_events": self._total_events,
                "events_in_buffer": len(self.events),
                "unique_ips": len(self._ip_counts),
                "protocols": dict(self._protocol_counts),
                "event_types": dict(self._event_type_counts),
                "top_ips": dict(self._ip_counts.most_common(20)),
                "credentials_captured": len(self._credentials),
            }

    def clear(self) -> None:
        """Clear all events and reset counters."""
        with self._lock:
            self.events.clear()
            self._protocol_counts.clear()
            self._event_type_counts.clear()
            self._ip_counts.clear()
            self._credentials.clear()
            self._total_events = 0


# Global singleton
event_store = EventStore()


def get_logger(name: str, config: Any = None) -> logging.Logger:
    """Create a configured logger with JSON formatting and optional file output."""
    logger = logging.getLogger(name)

    if logger.hasHandlers():
        return logger

    # Set level
    log_level = "INFO"
    if config and hasattr(config, "get"):
        log_level = config.get("logging", "level", default="INFO") or "INFO"
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    formatter = JSONFormatter()

    # Stream handler (stdout)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    # File handler with rotation
    if config and hasattr(config, "get"):
        log_dir = config.get("logging", "directory", default="./logs")
        if log_dir:
            log_path = Path(log_dir)
            log_path.mkdir(parents=True, exist_ok=True)
            log_file = log_path / f"{name.replace('.', '_')}.log"

            max_bytes_str = config.get("logging", "max_file_size", default="50MB") or "50MB"
            max_bytes = _parse_size(str(max_bytes_str))
            max_files = config.get("logging", "max_files", default=10) or 10

            file_handler = RotatingFileHandler(
                str(log_file), maxBytes=max_bytes, backupCount=int(max_files)
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger


def _parse_size(size_str: str) -> int:
    """Parse human-readable size string to bytes (e.g., '50MB' -> 52428800)."""
    size_str = size_str.strip().upper()
    multipliers = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}
    for suffix, mult in multipliers.items():
        if size_str.endswith(suffix):
            try:
                return int(float(size_str[: -len(suffix)]) * mult)
            except ValueError:
                break
    try:
        return int(size_str)
    except ValueError:
        return 50 * 1024 * 1024  # default 50MB
