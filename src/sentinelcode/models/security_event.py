from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityEvent:
    event_id: str
    timestamp: datetime
    agent: str
    tool: str
    action: str
    resource: str
    decision: str
    risk_score: int
    reason: str