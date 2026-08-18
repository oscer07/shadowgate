import json
import logging
import threading
from collections import deque
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional


class JSONFormatter(logging.Formatter):
    """Formats log records as JSON."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add any extra attributes
        for key, value in record.__dict__.items():
            if key not in ["args", "asctime", "created", "exc_info", "exc_text", "filename",
                           "funcName", "levelname", "levelno", "lineno", "module",
                           "msecs", "msg", "name", "pathname", "process",
                           "processName", "relativeCreated", "stack_info", "thread", "threadName"]:
                if key != "message":
                    log_data[key] = value
                    
        return json.dumps(log_data)


class EventStore:
    """Thread-safe in-memory event store for the dashboard."""

    def __init__(self, maxlen: int = 10000):
        self.events: deque = deque(maxlen=maxlen)
        self.lock = threading.Lock()

    def add_event(self, event: Dict[str, Any]) -> None:
        """Add an event to the store with an auto-timestamp."""
        if "timestamp" not in event:
            event["timestamp"] = datetime.utcnow().isoformat() + "Z"
        with self.lock:
            self.events.appendleft(event)

    def get_events(self, limit: int = 100, protocol: Optional[str] = None, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve events, optionally filtered by protocol or type."""
        with self.lock:
            filtered = []
            for event in self.events:
                if protocol and event.get("protocol") != protocol:
                    continue
                if event_type and event.get("event_type") != event_type:
                    continue
                filtered.append(event)
                if len(filtered) >= limit:
                    break
            return filtered

    def get_stats(self) -> Dict[str, Any]:
        """Return counts by protocol, event type, and top IPs."""
        stats = {
            "protocols": {},
            "event_types": {},
            "top_ips": {}
        }
        with self.lock:
            for event in self.events:
                # Protocol counts
                proto = event.get("protocol", "UNKNOWN")
                stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1
                
                # Event type counts
                etype = event.get("event_type", "UNKNOWN")
                stats["event_types"][etype] = stats["event_types"].get(etype, 0) + 1
                
                # Top IPs
                src_ip = event.get("src_ip")
                if src_ip:
                    stats["top_ips"][src_ip] = stats["top_ips"].get(src_ip, 0) + 1
                    
        # Sort top IPs
        stats["top_ips"] = dict(sorted(stats["top_ips"].items(), key=lambda item: item[1], reverse=True)[:10])
        return stats

    def clear(self) -> None:
        """Clear all events from the store."""
        with self.lock:
            self.events.clear()


# Global singleton
event_store = EventStore()


def get_logger(name: str, config: Any = None) -> logging.Logger:
    """Creates a configured logger with JSON formatting."""
    logger = logging.getLogger(name)
    
    # Avoid duplicate handlers
    if logger.hasHandlers():
        return logger
        
    logger.setLevel(logging.INFO)
    if config and hasattr(config, 'get'):
        log_level_str = config.get("logging", "level", default="INFO")
        logger.setLevel(getattr(logging, log_level_str.upper(), logging.INFO))
        
    formatter = JSONFormatter()
    
    # Stream Handler
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    
    # File Handler
    if config and hasattr(config, 'get'):
        log_file = config.get("logging", "file", default=None)
        if log_file:
            file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            
    return logger
