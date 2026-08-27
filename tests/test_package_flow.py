from sentinelcode.agent.simulated_agent import SimulatedAgent
from sentinelcode.detection.behavior_detector import BehaviorDetector

from tests.helpers import create_runtime


def test_package_installation_flows_through_sentinelcode():

    runtime = create_runtime()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    agent.install_package(
        "pip",
        "requests",
    )

    events = runtime.event_logger.get_events()

    detector = BehaviorDetector()

    threats = detector.analyze(events)

    package_threat = next(
        threat
        for threat in threats
        if threat.threat_type == "PACKAGE_INSTALLATION"
    )

    assert package_threat.severity == "MEDIUM"

    assert (
        package_threat.related_events[0].resource
        == "pip install requests"
    )