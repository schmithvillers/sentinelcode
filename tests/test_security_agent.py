from datetime import datetime, timezone
from unittest.mock import MagicMock

from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.security.security_agent import SecurityAgent


def make_event(**overrides):
    values = {
        "event_id": "event-123",
        "timestamp": datetime.now(timezone.utc),
        "agent": "simulated-agent",
        "tool": "filesystem",
        "action": "read",
        "resource": ".env",
        "decision": "BLOCK",
        "risk_score": 80,
        "reason": "Sensitive file access",
    }

    values.update(overrides)

    return SecurityEvent(**values)


def test_security_agent_detects_threat():
    gemini = MagicMock()

    gemini.analyze.return_value = """
    {
        "is_threat": true,
        "threat_type": "credential_access",
        "severity": "high",
        "reason": "The agent attempted to access a sensitive environment file."
    }
    """

    agent = SecurityAgent(gemini)

    event = make_event()

    result = agent.analyze_event(event)

    assert result is not None
    assert result.threat_type == "credential_access"
    assert result.severity == "high"
    assert result.related_events == [event]


def test_security_agent_returns_none_for_safe_event():
    gemini = MagicMock()

    gemini.analyze.return_value = """
    {
        "is_threat": false,
        "threat_type": "none",
        "severity": "low",
        "reason": "Normal source-code access."
    }
    """

    agent = SecurityAgent(gemini)

    event = make_event(
        resource="README.md",
        risk_score=5,
        reason="Normal documentation access",
    )

    result = agent.analyze_event(event)

    assert result is None


def test_security_agent_handles_invalid_gemini_response():
    gemini = MagicMock()

    gemini.analyze.return_value = "not valid json"

    agent = SecurityAgent(gemini)

    event = make_event()

    result = agent.analyze_event(event)

    assert result is None
def test_security_agent_sends_event_details_to_gemini():
    gemini = MagicMock()

    gemini.analyze.return_value = """
    {
        "is_threat": false,
        "threat_type": "none",
        "severity": "low",
        "reason": "Safe."
    }
    """

    agent = SecurityAgent(gemini)

    event = make_event(
        tool="shell",
        action="execute",
        resource="pytest",
        risk_score=10,
    )

    agent.analyze_event(event)

    prompt = gemini.analyze.call_args[0][0]

    assert "shell" in prompt
    assert "execute" in prompt
    assert "pytest" in prompt
    assert "10" in prompt