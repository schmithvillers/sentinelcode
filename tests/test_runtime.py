from sentinelcode.models.tool_request import ToolRequest

from sentinelcode.policy.policy_engine import PolicyEngine
from sentinelcode.policy.default_policy import DEFAULT_POLICY

from sentinelcode.risk.risk_engine import RiskEngine

from sentinelcode.runtime.runtime import SentinelRuntime
from sentinelcode.events.event_logger import EventLogger


def create_runtime():
    policy_engine = PolicyEngine(DEFAULT_POLICY)
    risk_engine = RiskEngine()
    event_logger = EventLogger()

    return SentinelRuntime(policy_engine, risk_engine, event_logger)


def test_runtime_blocks_env_access():
    runtime = create_runtime()

    request = ToolRequest(
        agent="coding-agent",
        tool="filesystem",
        action="read",
        resource=".env"
    )

    decision = runtime.evaluate_request(request)

    assert decision.decision == "BLOCK"
    assert decision.risk_score == 70


def test_runtime_allows_readme_access():
    runtime = create_runtime()

    request = ToolRequest(
        agent="coding-agent",
        tool="filesystem",
        action="read",
        resource="README.md"
    )

    decision = runtime.evaluate_request(request)

    assert decision.decision == "ALLOW"
    assert decision.risk_score == 5


def test_runtime_logs_event():
    runtime = create_runtime()

    request = ToolRequest(
        agent="coding-agent",
        tool="filesystem",
        action="read",
        resource=".env"
    )

    decision = runtime.evaluate_request(request)

    events = runtime.event_logger.get_events()

    assert decision.decision == "BLOCK"
    assert len(events) == 1

    event = events[0]

    assert event.agent == "coding-agent"
    assert event.tool == "filesystem"
    assert event.action == "read"
    assert event.resource == ".env"
    assert event.decision == "BLOCK"
    assert event.risk_score == 70
    assert event.reason == "Policy violation"
    assert event.event_id
    assert event.timestamp is not None


def test_runtime_logs_allowed_event():
    runtime = create_runtime()

    request = ToolRequest(
        agent="coding-agent",
        tool="filesystem",
        action="read",
        resource="README.md"
    )

    decision = runtime.evaluate_request(request)

    events = runtime.event_logger.get_events()

    assert decision.decision == "ALLOW"
    assert len(events) == 1

    event = events[0]

    assert event.agent == "coding-agent"
    assert event.tool == "filesystem"
    assert event.action == "read"
    assert event.resource == "README.md"
    assert event.decision == "ALLOW"
    assert event.risk_score == 5
    assert event.reason == "Action permitted"
    assert event.event_id
    assert event.timestamp is not None