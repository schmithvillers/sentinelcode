import os
import uuid

from google.cloud import pubsub_v1

from sentinelcode.events.pubsub_event_bus import (
    PubSubEventBus,
)

from sentinelcode.models.security_event import SecurityEvent

from datetime import datetime


def test_real_pubsub_publish():

    project_id = os.environ.get(
        "SENTINELCODE_GCP_PROJECT"
    )

    if not project_id:
        return

    publisher = pubsub_v1.PublisherClient()

    bus = PubSubEventBus(
        project_id=project_id,
        publisher=publisher,
    )

    event = SecurityEvent(
        event_id=f"test-{uuid.uuid4()}",
        timestamp=datetime.now(),
        agent="integration-test",
        tool="filesystem",
        action="read",
        resource="README.md",
        decision="ALLOW",
        risk_score=5,
        reason="Integration test",
    )

    bus.publish_security_event(event)