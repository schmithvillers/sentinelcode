from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityEvent:
    """
    Represents a recorded SentinelCode security event.
    """

    agent: str
    tool: str
    action: str
    resource: str
    decision: str
    risk_score: int
    reason: str
    timestamp: datetime