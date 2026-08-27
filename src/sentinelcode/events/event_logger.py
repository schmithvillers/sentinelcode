from sentinelcode.events.event_bus import EventBus
from sentinelcode.models.security_event import SecurityEvent


class EventLogger:

    def __init__(
        self,
        event_bus: EventBus | None = None,
    ):
        self._events: list[SecurityEvent] = []
        self.event_bus = event_bus

    def log(
        self,
        event: SecurityEvent,
    ) -> None:

        self._events.append(event)

        if self.event_bus is not None:
            self.event_bus.publish_security_event(event)

    def get_events(self) -> list[SecurityEvent]:

        return self._events.copy()

    def clear(self) -> None:

        self._events.clear()