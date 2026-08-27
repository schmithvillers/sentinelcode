from datetime import datetime

from sentinelcode.events.event_logger import EventLogger
from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.events.in_memory_event_bus import (
    InMemoryEventBus,
)

def create_test_event():
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


def test_logger_starts_empty():
    logger = EventLogger()

    assert logger.get_events() == []


def test_logger_stores_event():
    logger = EventLogger()
    event = create_test_event()

    logger.log(event)

    assert len(logger.get_events()) == 1
    assert logger.get_events()[0] == event


def test_logger_stores_multiple_events():
    logger = EventLogger()

    event1 = create_test_event()

    event2 = SecurityEvent(
        event_id="evt-002",
        timestamp=datetime.now(),
        agent="coding-agent",
        tool="shell",
        action="execute",
        resource="pytest",
        decision="ALLOW",
        risk_score=10,
        reason="Allowed command",
    )

    logger.log(event1)
    logger.log(event2)

    events = logger.get_events()

    assert len(events) == 2
    assert events[0] == event1
    assert events[1] == event2


def test_logger_clear():
    logger = EventLogger()

    logger.log(create_test_event())

    assert len(logger.get_events()) == 1

    logger.clear()

    assert logger.get_events() == []
def test_logger_publishes_to_event_bus():

    logger_bus = InMemoryEventBus()

    logger = EventLogger(
        event_bus=logger_bus,
    )

    event = create_test_event()

    logger.log(event)

    assert len(
        logger_bus.get_security_events()
    ) == 1

    assert (
        logger_bus.get_security_events()[0]
        == event
    )