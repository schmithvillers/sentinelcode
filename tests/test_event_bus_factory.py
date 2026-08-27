from sentinelcode.events.event_bus_factory import (
    create_event_bus,
)

from sentinelcode.events.in_memory_event_bus import (
    InMemoryEventBus,
)


def test_default_event_bus_is_memory(monkeypatch):

    monkeypatch.delenv(
        "SENTINELCODE_EVENT_BUS",
        raising=False,
    )

    bus = create_event_bus()

    assert isinstance(
        bus,
        InMemoryEventBus,
    )
def test_memory_event_bus_can_be_selected(monkeypatch):

    monkeypatch.setenv(
        "SENTINELCODE_EVENT_BUS",
        "memory",
    )

    bus = create_event_bus()

    assert isinstance(
        bus,
        InMemoryEventBus,
    )
from sentinelcode.events.pubsub_event_bus import (
    PubSubEventBus,
)


def test_pubsub_event_bus_can_be_selected(monkeypatch):

    monkeypatch.setenv(
        "SENTINELCODE_EVENT_BUS",
        "pubsub",
    )

    monkeypatch.setenv(
        "SENTINELCODE_GCP_PROJECT",
        "test-project",
    )

    bus = create_event_bus()

    assert isinstance(
        bus,
        PubSubEventBus,
    )