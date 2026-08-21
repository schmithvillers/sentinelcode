from sentinelcode.models.policy import Policy
from sentinelcode.policy.default_policy import DEFAULT_POLICY


def test_policy_creation():
    policy = Policy(
        name="test-policy",
        allowed_tools=["filesystem"],
        blocked_resources=[".env"],
        allowed_commands=["pytest"],
        allowed_network_hosts=["github.com"],
    )

    assert policy.name == "test-policy"
    assert "filesystem" in policy.allowed_tools
    assert ".env" in policy.blocked_resources
    assert "pytest" in policy.allowed_commands
    assert "github.com" in policy.allowed_network_hosts


def test_default_policy():
    assert "filesystem" in DEFAULT_POLICY.allowed_tools
    assert "shell" in DEFAULT_POLICY.allowed_tools
    assert "network" in DEFAULT_POLICY.allowed_tools

    assert ".env" in DEFAULT_POLICY.blocked_resources
    assert "id_rsa" in DEFAULT_POLICY.blocked_resources

    assert "pytest" in DEFAULT_POLICY.allowed_commands
    assert "github.com" in DEFAULT_POLICY.allowed_network_hosts