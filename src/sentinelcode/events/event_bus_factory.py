import os

from sentinelcode.events.event_bus import EventBus
from sentinelcode.events.in_memory_event_bus import (
    InMemoryEventBus,
)
from sentinelcode.events.pubsub_event_bus import (
    PubSubEventBus,
)


def create_event_bus() -> EventBus:

    mode = os.getenv(
        "SENTINELCODE_EVENT_BUS",
        "memory",
    )

    if mode == "pubsub":

        project_id = os.environ[
            "SENTINELCODE_GCP_PROJECT"
        ]

        return PubSubEventBus(
            project_id=project_id,
        )

    return InMemoryEventBus()