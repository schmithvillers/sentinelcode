from sentinelcode.agent.simulated_agent import SimulatedAgent

from tests.helpers import create_runtime


def test_agent_can_read_safe_file():

    runtime = create_runtime()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    decision = agent.read_file("README.md")

    assert decision.decision == "ALLOW"
    assert decision.risk_score == 5


def test_agent_cannot_read_env_file():

    runtime = create_runtime()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    decision = agent.read_file(".env")

    assert decision.decision == "BLOCK"
    assert decision.risk_score == 70


def test_agent_can_execute_pytest():

    runtime = create_runtime()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    decision = agent.execute_command("pytest")

    assert decision.decision == "ALLOW"
    assert decision.risk_score == 10


def test_agent_cannot_execute_sudo():

    runtime = create_runtime()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    decision = agent.execute_command("sudo something")

    assert decision.decision == "BLOCK"
    assert decision.risk_score == 90
def test_agent_can_access_allowed_network():

    runtime = create_runtime()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    decision = agent.network_request("github.com")

    assert decision.decision == "ALLOW"
    assert decision.risk_score == 35


def test_agent_cannot_access_unknown_network():

    runtime = create_runtime()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    decision = agent.network_request("attacker.com")

    assert decision.decision == "BLOCK"
    assert decision.risk_score == 35
def test_agent_can_request_package_installation():

    runtime = create_runtime()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    decision = agent.install_package(
        "pip",
        "requests",
    )

    assert decision.decision == "ALLOW"

    events = runtime.event_logger.get_events()

    assert len(events) == 1
    assert events[0].resource == "pip install requests"