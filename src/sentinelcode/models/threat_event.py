from dataclasses import dataclass
from datetime import datetime

from sentinelcode.models.security_event import SecurityEvent


@dataclass
class ThreatEvent:
    threat_type: str
    severity: str
    reason: str
    detected_at: datetime
    related_events: list[SecurityEvent]