from abc import ABC, abstractmethod

from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.models.threat_event import ThreatEvent


class EventBus(ABC):
    """
    Interface for publishing SentinelCode security events.
    """

    @abstractmethod
    def publish_security_event(
        self,
        event: SecurityEvent,
    ) -> None:
        pass

    @abstractmethod
    def publish_threat_event(
        self,
        threat: ThreatEvent,
    ) -> None:
        pass