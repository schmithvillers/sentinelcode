import json

from tests.helpers import (
    FakePublisher,
    create_threat_event,
)

from sentinelcode.events.in_memory_event_bus import (
    InMemoryEventBus,
)
from sentinelcode.events.pubsub_event_bus import (
    PubSubEventBus,
)
from sentinelcode.events.threat_publisher import (
    ThreatPublisher,
)


def test_threat_is_published():

    event_bus = InMemoryEventBus()

    publisher = ThreatPublisher(
        event_bus
    )

    threat = create_threat_event()

    publisher.publish(threat)

    threats = event_bus.get_threat_events()

    assert len(threats) == 1
    assert threats[0] == threat


def test_threat_event_is_published():

    publisher = FakePublisher()

    bus = PubSubEventBus(
        project_id="test-project",
        publisher=publisher,
    )

    threat = create_threat_event()

    bus.publish_threat_event(threat)

    assert len(publisher.messages) == 1

    message = publisher.messages[0]

    assert (
        message["topic"]
        == "projects/test-project/topics/"
        "sentinel-threat-events"
    )

    payload = json.loads(
        message["data"].decode("utf-8")
    )

    assert (
        payload["threat_type"]
        == "SENSITIVE_FILE_ACCESS"
    )

    assert payload["severity"] == "HIGH"

    assert payload["related_event_ids"] == [
        "evt-001"
    ]