from sentinelcode.agent.simulated_agent import SimulatedAgent
from sentinelcode.detection.behavior_detector import BehaviorDetector

from tests.helpers import create_runtime


def test_agent_behavior_can_be_analyzed():

    runtime = create_runtime()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    agent.read_file(".env")
    agent.network_request("attacker.com")

    events = runtime.event_logger.get_events()

    detector = BehaviorDetector()

    threats = detector.analyze(events)

    assert any(
        threat.threat_type == "SENSITIVE_FILE_ACCESS"
        for threat in threats
    )

    assert any(
        threat.threat_type == "POSSIBLE_SECRET_EXFILTRATION"
        for threat in threats
    )
    exfiltration_threat = next(
        threat
        for threat in threats
        if threat.threat_type == "POSSIBLE_SECRET_EXFILTRATION"
    )

    assert exfiltration_threat.severity == "CRITICAL"
    assert len(exfiltration_threat.related_events) == 2