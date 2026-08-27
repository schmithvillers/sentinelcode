from datetime import datetime

from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.models.threat_event import ThreatEvent
from sentinelcode.events.event_logger import EventLogger
from sentinelcode.events.in_memory_event_bus import (
    InMemoryEventBus,
)

from sentinelcode.policy.default_policy import DEFAULT_POLICY
from sentinelcode.policy.policy_engine import PolicyEngine
from sentinelcode.risk.risk_engine import RiskEngine
from sentinelcode.runtime.runtime import SentinelRuntime

def create_security_event():

    return SecurityEvent(
        event_id="evt-001",
        timestamp=datetime.now(),
        agent="coding-agent",
        tool="filesystem",
        action="read",
        resource=".env",
        decision="BLOCK",
        risk_score=70,
        reason="Sensitive file access",
    )


def create_threat_event():

    return ThreatEvent(
        threat_type="SENSITIVE_FILE_ACCESS",
        severity="HIGH",
        reason="Agent accessed a sensitive file.",
        detected_at=datetime.now(),
        related_events=[
            create_security_event()
        ],
    )
    
def create_runtime():

    event_bus = InMemoryEventBus()

    event_logger = EventLogger(
        event_bus=event_bus,
    )

    runtime = SentinelRuntime(
        PolicyEngine(DEFAULT_POLICY),
        RiskEngine(),
        event_logger,
    )

    return runtime


def create_runtime_with_bus():

    event_bus = InMemoryEventBus()

    event_logger = EventLogger(
        event_bus=event_bus,
    )

    runtime = SentinelRuntime(
        PolicyEngine(DEFAULT_POLICY),
        RiskEngine(),
        event_logger,
    )

    return runtime, event_bus
class FakeFuture:

    def result(self):
        return "message-id-001"


class FakePublisher:

    def __init__(self):
        self.messages = []

    def publish(self, topic, data):

        self.messages.append(
            {
                "topic": topic,
                "data": data,
            }
        )

        return FakeFuture()

class FakeBigQueryClient:

    def __init__(self):

        self.inserted_rows = []

    def insert_rows_json(
        self,
        table,
        rows,
    ):

        self.inserted_rows.append(
            {
                "table": table,
                "rows": rows,
            }
        )

        return []