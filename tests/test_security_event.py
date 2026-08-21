from datetime import datetime

from sentinelcode.models.security_event import SecurityEvent


def test_security_event_creation():

    event = SecurityEvent(
        agent="coding-agent",
        tool="filesystem",
        action="read",
        resource=".env",
        decision="BLOCK",
        risk_score=70,
        reason="Policy violation",
        timestamp=datetime.now()
    )


    assert event.agent == "coding-agent"
    assert event.decision == "BLOCK"
    assert event.risk_score == 70