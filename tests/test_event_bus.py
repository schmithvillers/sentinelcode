from datetime import datetime

from sentinelcode.events.in_memory_event_bus import (
    InMemoryEventBus,
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
        related_events=[],
    )


def test_event_bus_starts_empty():

    bus = InMemoryEventBus()

    assert bus.get_security_events() == []
    assert bus.get_threat_events() == []


def test_publish_security_event():

    bus = InMemoryEventBus()

    event = create_security_event()

    bus.publish_security_event(event)

    events = bus.get_security_events()

    assert len(events) == 1
    assert events[0] == event


def test_publish_threat_event():

    bus = InMemoryEventBus()

    threat = create_threat_event()

    bus.publish_threat_event(threat)

    threats = bus.get_threat_events()

    assert len(threats) == 1
    assert threats[0] == threat


def test_event_bus_can_store_multiple_events():

    bus = InMemoryEventBus()

    event1 = create_security_event()

    event2 = SecurityEvent(
        event_id="evt-002",
        timestamp=datetime.now(),
        agent="coding-agent",
        tool="shell",
        action="execute",
        resource="pytest",
        decision="ALLOW",
        risk_score=10,
        reason="Action permitted",
    )

    bus.publish_security_event(event1)
    bus.publish_security_event(event2)

    assert len(bus.get_security_events()) == 2


def test_event_bus_clear():

    bus = InMemoryEventBus()

    bus.publish_security_event(
        create_security_event()
    )

    bus.publish_threat_event(
        create_threat_event()
    )

    bus.clear()

    assert bus.get_security_events() == []
    assert bus.get_threat_events() == []