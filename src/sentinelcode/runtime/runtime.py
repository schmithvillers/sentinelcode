from sentinelcode.models.tool_request import ToolRequest
from sentinelcode.models.decision import Decision
from sentinelcode.models.security_event import SecurityEvent

from sentinelcode.policy.policy_engine import PolicyEngine
from sentinelcode.risk.risk_engine import RiskEngine
from sentinelcode.events.event_logger import EventLogger

from datetime import datetime
class SentinelRuntime:
    """
    Main SentinelCode security runtime.

    All agent actions pass through here.
    """
    def create_event( self, request: ToolRequest, decision: Decision ) -> SecurityEvent:

        return SecurityEvent(
            agent=request.agent,
            tool=request.tool,
            action=request.action,
            resource=request.resource,
            decision=decision.decision,
            risk_score=decision.risk_score,
            reason=decision.reason,
            timestamp=datetime.now()
        )

    def __init__( self, policy_engine: PolicyEngine, risk_engine: RiskEngine, event_logger: EventLogger ):
        self.policy_engine = policy_engine
        self.risk_engine = risk_engine
        self.event_logger = event_logger


    def evaluate_request( self, request: ToolRequest) -> Decision:
        allowed = self.policy_engine.evaluate(request)
        risk = self.risk_engine.calculate_risk(request)
        if not allowed:
                decision = Decision( decision="BLOCK", risk_score=risk, reason="Policy violation")

        else:
            decision = Decision( decision="ALLOW", risk_score=risk, reason="Action permitted")

        event = self.create_event( request, decision)

        self.event_logger.log(event)

        return decision
    def create_event( self, request: ToolRequest, decision: Decision ) -> SecurityEvent:

        return SecurityEvent(
            event_id=f"evt-{id(request)}",
            timestamp=datetime.now(),
            agent=request.agent,
            tool=request.tool,
            action=request.action,
            resource=request.resource,
            decision=decision.decision,
            risk_score=decision.risk_score,
            reason=decision.reason,
    )