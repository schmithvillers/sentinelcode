from sentinelcode.agent.simulated_agent import (
    SimulatedAgent,
)

from tests.helpers import create_runtime_with_bus


def test_security_event_flows_through_pipeline():

    runtime, event_bus = create_runtime_with_bus()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    agent.read_file("README.md")

    local_events = (
        runtime.event_logger.get_events()
    )

    published_events = (
        event_bus.get_security_events()
    )

    assert len(local_events) == 1
    assert len(published_events) == 1

    assert (
        published_events[0]
        == local_events[0]
    )
def test_multiple_events_are_published():

    runtime, event_bus = create_runtime_with_bus()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    agent.read_file("README.md")
    agent.execute_command("pytest")
    agent.network_request("github.com")

    events = event_bus.get_security_events()

    assert len(events) == 3

    assert events[0].resource == "README.md"
    assert events[1].resource == "pytest"
    assert events[2].resource == "github.com"
def test_blocked_event_is_published():

    runtime, event_bus = create_runtime_with_bus()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    decision = agent.read_file(".env")

    assert decision.decision == "BLOCK"

    events = event_bus.get_security_events()

    assert len(events) == 1
    assert events[0].decision == "BLOCK"
    assert events[0].resource == ".env"