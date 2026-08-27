from sentinelcode.events.event_bus import EventBus
from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.models.threat_event import ThreatEvent


class InMemoryEventBus(EventBus):
    """
    Local event bus used for development and testing.
    """

    def __init__(self):
        self.security_events: list[SecurityEvent] = []
        self.threat_events: list[ThreatEvent] = []

    def publish_security_event(
        self,
        event: SecurityEvent,
    ) -> None:

        self.security_events.append(event)

    def publish_threat_event(
        self,
        threat: ThreatEvent,
    ) -> None:

        self.threat_events.append(threat)

    def get_security_events(self) -> list[SecurityEvent]:

        return self.security_events.copy()

    def get_threat_events(self) -> list[ThreatEvent]:

        return self.threat_events.copy()

    def clear(self) -> None:

        self.security_events.clear()
        self.threat_events.clear()