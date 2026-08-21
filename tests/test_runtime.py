from sentinelcode.models.tool_request import ToolRequest

from sentinelcode.policy.policy_engine import PolicyEngine
from sentinelcode.policy.default_policy import DEFAULT_POLICY

from sentinelcode.risk.risk_engine import RiskEngine

from sentinelcode.runtime.runtime import SentinelRuntime



def create_runtime():

    policy_engine = PolicyEngine(
        DEFAULT_POLICY
    )

    risk_engine = RiskEngine()

    return SentinelRuntime(
        policy_engine,
        risk_engine
    )



def test_runtime_blocks_env_access():

    runtime = create_runtime()


    request = ToolRequest(
        agent="coding-agent",
        tool="filesystem",
        action="read",
        resource=".env"
    )


    decision = runtime.evaluate_request(
        request
    )


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


    decision = runtime.evaluate_request(
        request
    )


    assert decision.decision == "ALLOW"
    assert decision.risk_score == 5