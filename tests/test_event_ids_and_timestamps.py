from datetime import datetime, timezone

from sentinelcode.models.security_event import SecurityEvent


def create_event():
    return SecurityEvent(
        agent="coding-agent",
        tool="filesystem",
        action="read",
        resource=".env",
        decision="BLOCK",
        risk_score=70,
        reason="Sensitive file access",
    )


def test_event_id_is_generated():
    event = create_event()

    assert event.event_id
    assert isinstance(event.event_id, str)


def test_event_ids_are_unique():
    event1 = create_event()
    event2 = create_event()

    assert event1.event_id != event2.event_id


def test_timestamp_is_generated():
    event = create_event()

    assert event.timestamp is not None
    assert isinstance(event.timestamp, datetime)


def test_timestamp_is_utc():
    event = create_event()

    assert event.timestamp.tzinfo is not None
    assert event.timestamp.utcoffset() == timezone.utc.utcoffset(event.timestamp)


def test_timestamp_is_generated_for_each_event():
    event1 = create_event()
    event2 = create_event()

    assert event1.timestamp is not None
    assert event2.timestamp is not None