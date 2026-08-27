import json

from sentinelcode.workers.security_event_worker import (
    SecurityEventWorker,
)

from tests.helpers import (
    FakeBigQueryClient,
    create_security_event,
)


def test_worker_processes_security_event():

    client = FakeBigQueryClient()

    from sentinelcode.storage.bigquery_store import (
        BigQueryStore,
    )

    store = BigQueryStore(
        project_id="test-project",
        client=client,
    )

    worker = SecurityEventWorker(
        store
    )

    event = create_security_event()

    message = json.dumps(
        {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "agent": event.agent,
            "tool": event.tool,
            "action": event.action,
            "resource": event.resource,
            "decision": event.decision,
            "risk_score": event.risk_score,
            "reason": event.reason,
        }
    ).encode("utf-8")

    worker.process(message)

    assert len(
        client.inserted_rows
    ) == 1

    row = (
        client
        .inserted_rows[0]
        ["rows"][0]
    )

    assert row["event_id"] == "evt-001"
    assert row["decision"] == "BLOCK"
    assert row["risk_score"] == 70