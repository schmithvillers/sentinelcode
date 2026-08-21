from sentinelcode.models.tool_request import ToolRequest
from sentinelcode.risk.risk_engine import RiskEngine


def test_low_risk_file_read():
    engine = RiskEngine()

    request = ToolRequest(
        agent="coding-agent",
        tool="filesystem",
        action="read",
        resource="README.md",
    )

    risk = engine.calculate_risk(request)

    assert risk == 5


def test_env_file_is_high_risk():
    engine = RiskEngine()

    request = ToolRequest(
        agent="coding-agent",
        tool="filesystem",
        action="read",
        resource=".env",
    )

    risk = engine.calculate_risk(request)

    assert risk == 70


def test_ssh_key_is_high_risk():
    engine = RiskEngine()

    request = ToolRequest(
        agent="coding-agent",
        tool="filesystem",
        action="read",
        resource="/Users/test/.ssh/id_rsa",
    )

    risk = engine.calculate_risk(request)

    assert risk == 90


def test_pytest_is_low_risk():
    engine = RiskEngine()

    request = ToolRequest(
        agent="coding-agent",
        tool="shell",
        action="execute",
        resource="pytest",
    )

    risk = engine.calculate_risk(request)

    assert risk == 10


def test_sudo_is_high_risk():
    engine = RiskEngine()

    request = ToolRequest(
        agent="coding-agent",
        tool="shell",
        action="execute",
        resource="sudo something",
    )

    risk = engine.calculate_risk(request)

    assert risk == 90


def test_rm_rf_is_critical_risk():
    engine = RiskEngine()

    request = ToolRequest(
        agent="coding-agent",
        tool="shell",
        action="execute",
        resource="rm -rf /",
    )

    risk = engine.calculate_risk(request)

    assert risk == 100


def test_network_request():
    engine = RiskEngine()

    request = ToolRequest(
        agent="coding-agent",
        tool="network",
        action="request",
        resource="github.com",
    )

    risk = engine.calculate_risk(request)

    assert risk == 35