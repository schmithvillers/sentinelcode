import json
from datetime import datetime
from tests.helpers import FakePublisher
from sentinelcode.events.pubsub_event_bus import (
    PubSubEventBus,
)

from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.models.threat_event import ThreatEvent


def create_security_event():

    return SecurityEvent(
        event_id="evt-001",
        timestamp=datetime.now(),
        agent="coding-agent",
        tool="filesystem",
        action="read",
        resource=".env",
        decision="BLOCK",
        risk_score=70,
        reason="Sensitive file access",
    )


def create_threat_event():

    return ThreatEvent(
        threat_type="SENSITIVE_FILE_ACCESS",
        severity="HIGH",
        reason="Agent accessed a sensitive file.",
        detected_at=datetime.now(),
        related_events=[
            create_security_event()
        ],
    )

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