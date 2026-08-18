from abc import ABC, abstractmethod
from shadowgate.config import Config
import logging

class BaseHoneypot(ABC):
    """Base class for all honeypot protocol implementations."""
    
    PROTOCOL: str = "unknown"
    
    def __init__(self, config: Config):
        self.config = config
        self._running = False
        self.logger = logging.getLogger(f"shadowgate.honeypot.{self.PROTOCOL}")
        
    @abstractmethod
    async def start(self) -> None: ...
    
    @abstractmethod
    async def stop(self) -> None: ...
    
    def _record_event(self, event_type: str, source_ip: str, **kwargs) -> dict:
        """Record a honeypot event with standard fields."""
        import time
        event = {
            "timestamp": time.time(),
            "protocol": self.PROTOCOL,
            "event_type": event_type,
            "source_ip": source_ip,
            **kwargs
        }
        # Log the event and store in shared event store
        try:
            from shadowgate.logging.logger import event_store
            event_store.add_event(event)
        except ImportError:
            pass
        return event
