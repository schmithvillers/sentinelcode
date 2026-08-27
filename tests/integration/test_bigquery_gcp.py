import os
import uuid
from datetime import datetime

from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.storage.bigquery_store import (
    BigQueryStore,
)


def test_real_bigquery_insert():

    project_id = os.environ.get(
        "SENTINELCODE_GCP_PROJECT"
    )

    if not project_id:
        return

    store = BigQueryStore(
        project_id=project_id,
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
        reason="BigQuery integration test",
    )

    store.insert_security_event(event)