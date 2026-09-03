from datetime import datetime, timezone

from sentinelcode.events.event_logger import EventLogger
from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.models.threat_event import ThreatEvent


def make_event(**overrides):
    values = {
        "event_id": "event-123",
        "timestamp": datetime.now(timezone.utc),
        "agent": "coding-agent",
        "tool": "filesystem",
        "action": "read",
        "resource": ".env",
        "decision": "BLOCK",
        "risk_score": 70,
        "reason": "Policy violation",
    }

    values.update(overrides)

    return SecurityEvent(**values)


def make_threat(event):
    return ThreatEvent(
        threat_type="SENSITIVE_FILE_ACCESS",
        severity="HIGH",
        reason="Agent accessed a sensitive file.",
        detected_at=datetime.now(timezone.utc),
        related_events=[event],
    )


def test_event_logger_without_security_analyzer_still_works():
    logger = EventLogger()

    event = make_event()

    logger.log(event)

    assert logger.get_events() == [event]
    assert logger.get_threats() == []


def test_event_logger_runs_security_analyzer():
    analyzed_events = []

    def analyzer(event):
        analyzed_events.append(event)
        return []

    logger = EventLogger(
        security_analyzer=analyzer,
    )

    event = make_event()

    logger.log(event)

    assert logger.get_events() == [event]
    assert analyzed_events == [event]


def test_event_logger_stores_detected_threats():
    event = make_event()
    threat = make_threat(event)

    def analyzer(analyzed_event):
        assert analyzed_event == event
        return [threat]

    logger = EventLogger(
        security_analyzer=analyzer,
    )

    logger.log(event)

    threats = logger.get_threats()

    assert len(threats) == 1
    assert threats[0] == threat


def test_event_logger_stores_multiple_threats():
    event = make_event()

    threat_1 = make_threat(event)

    threat_2 = ThreatEvent(
        threat_type="POSSIBLE_SECRET_EXFILTRATION",
        severity="CRITICAL",
        reason="Sensitive file access was followed by network activity.",
        detected_at=datetime.now(timezone.utc),
        related_events=[event],
    )

    def analyzer(analyzed_event):
        return [threat_1, threat_2]

    logger = EventLogger(
        security_analyzer=analyzer,
    )

    logger.log(event)

    threats = logger.get_threats()

    assert len(threats) == 2
    assert threats[0].threat_type == "SENSITIVE_FILE_ACCESS"
    assert threats[1].threat_type == "POSSIBLE_SECRET_EXFILTRATION"


def test_event_logger_clear_removes_events_and_threats():
    event = make_event()
    threat = make_threat(event)

    def analyzer(analyzed_event):
        return [threat]

    logger = EventLogger(
        security_analyzer=analyzer,
    )

    logger.log(event)

    assert len(logger.get_events()) == 1
    assert len(logger.get_threats()) == 1

    logger.clear()

    assert logger.get_events() == []
    assert logger.get_threats() == []


def test_event_logger_runs_sequence_analyzer():
    analyzed_sequences = []

    def sequence_analyzer(events):
        analyzed_sequences.append(events.copy())
        return []

    logger = EventLogger(
        sequence_analyzer=sequence_analyzer,
    )

    event_1 = make_event(
        event_id="event-1",
        resource=".env",
    )

    event_2 = make_event(
        event_id="event-2",
        tool="shell",
        action="execute",
        resource="base64 .env",
    )

    logger.log(event_1)
    logger.log(event_2)

    assert len(analyzed_sequences) == 2

    assert len(analyzed_sequences[0]) == 1
    assert len(analyzed_sequences[1]) == 2

    assert analyzed_sequences[1][0] == event_1
    assert analyzed_sequences[1][1] == event_2


def test_event_logger_stores_sequence_threats():
    event_1 = make_event(
        event_id="event-1",
        resource=".env",
    )

    event_2 = make_event(
        event_id="event-2",
        tool="network",
        action="request",
        resource="example.com",
    )

    sequence_threat = ThreatEvent(
        threat_type="POSSIBLE_SECRET_EXFILTRATION",
        severity="CRITICAL",
        reason="Sensitive file access was followed by network activity.",
        detected_at=datetime.now(timezone.utc),
        related_events=[event_1, event_2],
    )

    def sequence_analyzer(events):
        if len(events) == 2:
            return [sequence_threat]

        return []

    logger = EventLogger(
        sequence_analyzer=sequence_analyzer,
    )

    logger.log(event_1)
    logger.log(event_2)

    threats = logger.get_threats()

    assert len(threats) == 1
    assert threats[0].threat_type == "POSSIBLE_SECRET_EXFILTRATION"
    assert threats[0].related_events == [event_1, event_2]