from sentinelcode.models.tool_request import ToolRequest


def test_tool_request_creation():
    request = ToolRequest(
        agent="coding-agent",
        tool="filesystem",
        action="read",
        resource=".env"
    )

    assert request.agent == "coding-agent"
    assert request.tool == "filesystem"
    assert request.action == "read"
    assert request.resource == ".env"