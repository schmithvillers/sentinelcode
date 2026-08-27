import json

from tests.helpers import (
    FakePublisher,
    create_security_event,
)

from sentinelcode.events.pubsub_event_bus import (
    PubSubEventBus,
)


def test_security_event_creation():
    ...

def test_security_event_is_published():

    publisher = FakePublisher()

    bus = PubSubEventBus(
        project_id="test-project",
        publisher=publisher,
    )

    event = create_security_event()

    bus.publish_security_event(event)

    assert len(publisher.messages) == 1

    message = publisher.messages[0]

    assert (
        message["topic"]
        == "projects/test-project/topics/"
        "sentinel-security-events"
    )

    payload = json.loads(
        message["data"].decode("utf-8")
    )

    assert payload["event_id"] == "evt-001"
    assert payload["agent"] == "coding-agent"
    assert payload["resource"] == ".env"
    assert payload["decision"] == "BLOCK"
    assert payload["risk_score"] == 70