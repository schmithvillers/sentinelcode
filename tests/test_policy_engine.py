from sentinelcode.models.tool_request import ToolRequest
from sentinelcode.policy.policy_engine import PolicyEngine
from sentinelcode.policy.default_policy import DEFAULT_POLICY



def test_allowed_file_read():

    engine = PolicyEngine(DEFAULT_POLICY)

    request = ToolRequest(
        agent="coding-agent",
        tool="filesystem",
        action="read",
        resource="README.md"
    )

    result = engine.evaluate(request)

    assert result is True



def test_blocked_env_access():

    engine = PolicyEngine(DEFAULT_POLICY)

    request = ToolRequest(
        agent="coding-agent",
        tool="filesystem",
        action="read",
        resource=".env"
    )

    result = engine.evaluate(request)

    assert result is False



def test_allowed_shell_command():

    engine = PolicyEngine(DEFAULT_POLICY)

    request = ToolRequest(
        agent="coding-agent",
        tool="shell",
        action="execute",
        resource="pytest"
    )

    result = engine.evaluate(request)

    assert result is True



def test_blocked_shell_command():

    engine = PolicyEngine(DEFAULT_POLICY)

    request = ToolRequest(
        agent="coding-agent",
        tool="shell",
        action="execute",
        resource="sudo rm -rf /"
    )

    result = engine.evaluate(request)

    assert result is False



def test_allowed_network():

    engine = PolicyEngine(DEFAULT_POLICY)

    request = ToolRequest(
        agent="coding-agent",
        tool="network",
        action="request",
        resource="github.com"
    )

    result = engine.evaluate(request)

    assert result is True



def test_blocked_network():

    engine = PolicyEngine(DEFAULT_POLICY)

    request = ToolRequest(
        agent="coding-agent",
        tool="network",
        action="request",
        resource="attacker.com"
    )

    result = engine.evaluate(request)

    assert result is False
    