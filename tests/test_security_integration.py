from sentinelcode.agent.simulated_agent import SimulatedAgent

from tests.helpers import create_security_runtime


def test_suspicious_action_sequence_flows_through_runtime():
    runtime, event_bus, security_orchestrator, gemini = (
        create_security_runtime()
    )

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    # Step 1: Agent accesses a sensitive file.
    agent.read_file(".env")

    # Step 2: Agent transforms the data.
    agent.execute_command("base64 .env")

    # Step 3: Agent sends data to a network destination.
    agent.network_request("example.com")

    events = runtime.event_logger.get_events()
    threats = runtime.event_logger.get_threats()

    assert len(events) == 3

    assert events[0].resource == ".env"
    assert events[1].resource == "base64 .env"
    assert events[2].resource == "example.com"

    threat_types = {
        threat.threat_type
        for threat in threats
    }

    assert "SENSITIVE_FILE_ACCESS" in threat_types
    assert "POSSIBLE_SECRET_EXFILTRATION" in threat_types
    assert "SUSPICIOUS_SHELL_NETWORK_ACTIVITY" in threat_types
    assert "SUSPICIOUS_ACTION_SEQUENCE" in threat_types

    suspicious_sequence_threats = [
        threat
        for threat in threats
        if threat.threat_type == "SUSPICIOUS_ACTION_SEQUENCE"
    ]

    assert len(suspicious_sequence_threats) == 1

    sequence_threat = suspicious_sequence_threats[0]

    assert sequence_threat.severity == "CRITICAL"
    assert (
        sequence_threat.related_events
        == events
    )

    # Gemini should have been called for each individual event.
    assert gemini.analyze.call_count == 3

    # The events should still have been published normally.
    published_events = event_bus.get_security_events()

    assert len(published_events) == 3