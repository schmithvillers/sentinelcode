from collections.abc import Callable

from sentinelcode.events.event_bus import EventBus
from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.models.threat_event import ThreatEvent


class EventLogger:
    def __init__(
        self,
        event_bus: EventBus | None = None,
        security_analyzer: Callable[
            [SecurityEvent], list[ThreatEvent]
        ] | None = None,
        sequence_analyzer: Callable[
            [list[SecurityEvent]], list[ThreatEvent]
        ] | None = None,
    ):
        self._events: list[SecurityEvent] = []
        self.event_bus = event_bus
        self.security_analyzer = security_analyzer
        self.sequence_analyzer = sequence_analyzer
        self._threats: list[ThreatEvent] = []

    def log(
        self,
        event: SecurityEvent,
    ) -> None:
        self._events.append(event)

        if self.event_bus is not None:
            self.event_bus.publish_security_event(event)

        if self.security_analyzer is not None:
            threats = self.security_analyzer(event)
            self._threats.extend(threats)

        if self.sequence_analyzer is not None:
            threats = self.sequence_analyzer(self._events.copy())
            self._threats.extend(threats)

    def get_events(self) -> list[SecurityEvent]:
        return self._events.copy()

    def get_threats(self) -> list[ThreatEvent]:
        return self._threats.copy()

    def clear(self) -> None:
        self._events.clear()
        self._threats.clear()