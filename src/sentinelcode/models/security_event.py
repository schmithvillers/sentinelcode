from dataclasses import dataclass, field
from datetime import datetime, timezone
import uuid


@dataclass
class SecurityEvent:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    agent: str = ""
    tool: str = ""
    action: str = ""
    resource: str = ""
    decision: str = ""
    risk_score: int = 0
    reason: str = ""