from datetime import datetime

from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.models.threat_event import ThreatEvent


def create_event():
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


def test_threat_event_creation():

    event = create_event()

    detected_at = datetime.now()

    threat = ThreatEvent(
        threat_type="SENSITIVE_FILE_ACCESS",
        severity="HIGH",
        reason="Agent accessed a sensitive file.",
        detected_at=detected_at,
        related_events=[event],
    )

    assert threat.threat_type == "SENSITIVE_FILE_ACCESS"
    assert threat.severity == "HIGH"
    assert threat.reason == "Agent accessed a sensitive file."
    assert threat.detected_at == detected_at
    assert len(threat.related_events) == 1
    assert threat.related_events[0] == event