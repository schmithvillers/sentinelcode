from sentinelcode.models.tool_request import ToolRequest

from sentinelcode.policy.default_policy import DEFAULT_POLICY
from sentinelcode.policy.policy_engine import PolicyEngine

from sentinelcode.risk.risk_engine import RiskEngine

from sentinelcode.runtime.runtime import SentinelRuntime



def main():

    runtime = SentinelRuntime(
        PolicyEngine(DEFAULT_POLICY),
        RiskEngine()
    )


    requests = [

        ToolRequest(
            agent="coding-agent",
            tool="filesystem",
            action="read",
            resource="README.md"
        ),

        ToolRequest(
            agent="coding-agent",
            tool="filesystem",
            action="read",
            resource=".env"
        )

    ]


    for request in requests:

        decision = runtime.evaluate_request(request)


        print("-------------------------")
        print("Agent Action")
        print("-------------------------")

        print(request)

        print()

        print("Decision:")
        print(decision.decision)

        print("Risk:")
        print(decision.risk_score)

        print("Reason:")
        print(decision.reason)



if __name__ == "__main__":
    main()