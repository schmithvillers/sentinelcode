from sentinelcode.events.event_bus import EventBus
from sentinelcode.models.threat_event import ThreatEvent


class ThreatPublisher:

    def __init__(
        self,
        event_bus: EventBus,
    ):
        self.event_bus = event_bus

    def publish(
        self,
        threat: ThreatEvent,
    ) -> None:

        self.event_bus.publish_threat_event(
            threat
        )