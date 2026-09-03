from datetime import datetime, timezone
from unittest.mock import MagicMock

from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.security.security_orchestrator import SecurityOrchestrator


def make_event(**overrides):
    values = {
        "event_id": "event-123",
        "timestamp": datetime.now(timezone.utc),
        "agent": "coding-agent",
        "tool": "filesystem",
        "action": "read",
        "resource": "README.md",
        "decision": "ALLOW",
        "risk_score": 5,
        "reason": "Normal file access",
    }

    values.update(overrides)

    return SecurityEvent(**values)


def test_orchestrator_returns_gemini_threat():
    security_agent = MagicMock()

    gemini_threat = MagicMock()
    gemini_threat.threat_type = "credential_access"

    security_agent.analyze_event.return_value = gemini_threat

    orchestrator = SecurityOrchestrator(security_agent)

    event = make_event(
        resource=".env",
        decision="BLOCK",
        risk_score=70,
        reason="Policy violation",
    )

    threats = orchestrator.analyze_event(event)

    assert len(threats) == 1
    assert threats[0] == gemini_threat

    security_agent.analyze_event.assert_called_once_with(event)


def test_orchestrator_returns_no_threat_for_safe_event():
    security_agent = MagicMock()

    security_agent.analyze_event.return_value = None

    orchestrator = SecurityOrchestrator(security_agent)

    event = make_event()

    threats = orchestrator.analyze_event(event)

    assert threats == []

    security_agent.analyze_event.assert_called_once_with(event)


def test_orchestrator_detects_deterministic_sensitive_file_access():
    security_agent = MagicMock()

    orchestrator = SecurityOrchestrator(security_agent)

    event = make_event(
        resource=".env",
        decision="BLOCK",
        risk_score=70,
        reason="Policy violation",
    )

    threats = orchestrator.analyze_events([event])

    assert len(threats) == 1
    assert threats[0].threat_type == "SENSITIVE_FILE_ACCESS"
    assert threats[0].severity == "HIGH"

    # Sequence analysis is deterministic and does not call Gemini.
    security_agent.analyze_event.assert_not_called()


def test_orchestrator_detects_multi_event_sequence():
    security_agent = MagicMock()

    orchestrator = SecurityOrchestrator(security_agent)

    events = [
        make_event(
            event_id="event-1",
            resource=".env",
            decision="BLOCK",
            risk_score=70,
            reason="Policy violation",
        ),
        make_event(
            event_id="event-2",
            tool="shell",
            action="execute",
            resource="base64 .env",
            decision="ALLOW",
            risk_score=20,
            reason="Shell command",
        ),
        make_event(
            event_id="event-3",
            tool="network",
            action="request",
            resource="example.com",
            decision="ALLOW",
            risk_score=30,
            reason="Network request",
        ),
    ]

    threats = orchestrator.analyze_events(events)

    threat_types = {
        threat.threat_type
        for threat in threats
    }

    assert "SENSITIVE_FILE_ACCESS" in threat_types
    assert "POSSIBLE_SECRET_EXFILTRATION" in threat_types
    assert "SUSPICIOUS_SHELL_NETWORK_ACTIVITY" in threat_types
    assert "SUSPICIOUS_ACTION_SEQUENCE" in threat_types

    # Multi-event deterministic analysis does not call Gemini.
    security_agent.analyze_event.assert_not_called()


def test_orchestrator_analyzes_single_event_contextually():
    security_agent = MagicMock()

    security_agent.analyze_event.return_value = None

    orchestrator = SecurityOrchestrator(security_agent)

    event = make_event(
        tool="shell",
        action="execute",
        resource="pytest",
        risk_score=10,
    )

    threats = orchestrator.analyze_event(event)

    assert threats == []

    security_agent.analyze_event.assert_called_once_with(event)