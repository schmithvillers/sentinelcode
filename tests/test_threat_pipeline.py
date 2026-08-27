from sentinelcode.agent.simulated_agent import (
    SimulatedAgent,
)

from sentinelcode.detection.behavior_detector import (
    BehaviorDetector,
)

from sentinelcode.events.threat_publisher import (
    ThreatPublisher,
)

from tests.helpers import create_runtime_with_bus


def test_detected_threat_flows_to_event_bus():

    runtime, event_bus = create_runtime_with_bus()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    agent.read_file(".env")
    agent.network_request("attacker.com")

    events = runtime.event_logger.get_events()

    detector = BehaviorDetector()

    threats = detector.analyze(events)

    publisher = ThreatPublisher(
        event_bus
    )

    for threat in threats:
        publisher.publish(threat)

    published_threats = (
        event_bus.get_threat_events()
    )

    assert len(published_threats) >= 1

    assert any(
        threat.threat_type
        == "POSSIBLE_SECRET_EXFILTRATION"
        for threat in published_threats
    )