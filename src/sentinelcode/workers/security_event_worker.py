import json
from datetime import datetime

from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.storage.bigquery_store import BigQueryStore


class SecurityEventWorker:
    """
    Processes security events and persists them to BigQuery.
    """

    def __init__(
        self,
        store: BigQueryStore,
    ):
        self.store = store

    def process(
        self,
        message: bytes,
    ) -> None:

        data = json.loads(
            message.decode("utf-8")
        )

        event = SecurityEvent(
            event_id=data["event_id"],
            timestamp=datetime.fromisoformat(
                data["timestamp"]
            ),
            agent=data["agent"],
            tool=data["tool"],
            action=data["action"],
            resource=data["resource"],
            decision=data["decision"],
            risk_score=data["risk_score"],
            reason=data["reason"],
        )

        self.store.insert_security_event(event)