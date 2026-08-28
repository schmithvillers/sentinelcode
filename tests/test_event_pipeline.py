import json

from sentinelcode.agent.simulated_agent import SimulatedAgent
from sentinelcode.events.event_logger import EventLogger
from sentinelcode.events.pubsub_event_bus import PubSubEventBus
from sentinelcode.policy.default_policy import DEFAULT_POLICY
from sentinelcode.policy.policy_engine import PolicyEngine
from sentinelcode.risk.risk_engine import RiskEngine
from sentinelcode.runtime.runtime import SentinelRuntime
from sentinelcode.storage.bigquery_store import BigQueryStore
from sentinelcode.workers.security_event_worker import SecurityEventWorker

from tests.helpers import (
    FakeBigQueryClient,
    FakePublisher,
    create_runtime_with_bus,
)


def test_security_event_flows_through_pipeline():
    runtime, event_bus = create_runtime_with_bus()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    agent.read_file("README.md")

    local_events = runtime.event_logger.get_events()
    published_events = event_bus.get_security_events()

    assert len(local_events) == 1
    assert len(published_events) == 1

    assert published_events[0] == local_events[0]


def test_multiple_events_are_published():
    runtime, event_bus = create_runtime_with_bus()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    agent.read_file("README.md")
    agent.execute_command("pytest")
    agent.network_request("github.com")

    events = event_bus.get_security_events()

    assert len(events) == 3

    assert events[0].resource == "README.md"
    assert events[1].resource == "pytest"
    assert events[2].resource == "github.com"


def test_blocked_event_is_published():
    runtime, event_bus = create_runtime_with_bus()

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    decision = agent.read_file(".env")

    assert decision.decision == "BLOCK"

    events = event_bus.get_security_events()

    assert len(events) == 1
    assert events[0].decision == "BLOCK"
    assert events[0].resource == ".env"


def test_security_event_flows_from_runtime_to_bigquery():
    publisher = FakePublisher()

    event_bus = PubSubEventBus(
        project_id="test-project",
        publisher=publisher,
    )

    event_logger = EventLogger(
        event_bus=event_bus,
    )

    runtime = SentinelRuntime(
        PolicyEngine(DEFAULT_POLICY),
        RiskEngine(),
        event_logger,
    )

    agent = SimulatedAgent(
        name="coding-agent",
        runtime=runtime,
    )

    agent.read_file(".env")

    # Verify the runtime created an event.
    local_events = runtime.event_logger.get_events()

    assert len(local_events) == 1

    event = local_events[0]

    # Verify the event was published to Pub/Sub.
    assert len(publisher.messages) == 1

    message = publisher.messages[0]

    assert (
        message["topic"]
        == "projects/test-project/topics/"
        "sentinel-security-events"
    )

    payload = message["data"]

    data = json.loads(
        payload.decode("utf-8")
    )

    assert data["event_id"] == event.event_id
    assert data["timestamp"] == event.timestamp.isoformat()
    assert data["agent"] == "coding-agent"
    assert data["tool"] == "filesystem"
    assert data["action"] == "read"
    assert data["resource"] == ".env"
    assert data["decision"] == "BLOCK"
    assert data["risk_score"] == 70
    assert data["reason"] == "Policy violation"

    # Consume the Pub/Sub message.
    client = FakeBigQueryClient()

    store = BigQueryStore(
        project_id="test-project",
        client=client,
    )

    worker = SecurityEventWorker(store)

    worker.process(payload)

    # Verify that the worker stored the event in BigQuery.
    assert len(client.inserted_rows) == 1

    row = client.inserted_rows[0]["rows"][0]

    assert row["event_id"] == event.event_id
    assert row["timestamp"] == event.timestamp.isoformat()
    assert row["agent"] == "coding-agent"
    assert row["tool"] == "filesystem"
    assert row["action"] == "read"
    assert row["resource"] == ".env"
    assert row["decision"] == "BLOCK"
    assert row["risk_score"] == 70
    assert row["reason"] == "Policy violation"