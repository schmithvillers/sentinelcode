import json

from sentinelcode.agent.simulated_agent import (
    SimulatedAgent,
)

from sentinelcode.storage.bigquery_store import (
    BigQueryStore,
)

from sentinelcode.workers.security_event_worker import (
    SecurityEventWorker,
)

from tests.helpers import (
    FakeBigQueryClient,
    create_runtime_with_bus,
)


def test_security_event_reaches_bigquery():

    runtime, event_bus = create_runtime_with_bus()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    agent.read_file(".env")

    events = event_bus.get_security_events()

    assert len(events) == 1

    event = events[0]

    payload = json.dumps(
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

    client = FakeBigQueryClient()

    store = BigQueryStore(
        project_id="test-project",
        client=client,
    )

    worker = SecurityEventWorker(
        store
    )

    worker.process(payload)

    assert len(
        client.inserted_rows
    ) == 1

    row = (
        client
        .inserted_rows[0]
        ["rows"][0]
    )

    assert row["resource"] == ".env"
    assert row["decision"] == "BLOCK"