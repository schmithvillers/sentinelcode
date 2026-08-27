from google.cloud import bigquery

from sentinelcode.models.security_event import SecurityEvent


class BigQueryStore:
    """
    Stores SentinelCode security events in BigQuery.
    """

    def __init__(
        self,
        project_id: str,
        dataset_id: str = "sentinelcode_security",
        table_id: str = "security_events",
        client=None,
    ):
        self.project_id = project_id
        self.dataset_id = dataset_id
        self.table_id = table_id

        self.table_ref = (
            f"{project_id}."
            f"{dataset_id}."
            f"{table_id}"
        )

        self.client = (
            client
            if client is not None
            else bigquery.Client(
                project=project_id
            )
        )

    def insert_security_event(
        self,
        event: SecurityEvent,
    ) -> None:

        row = {
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

        errors = self.client.insert_rows_json(
            self.table_ref,
            [row],
        )

        if errors:
            raise RuntimeError(
                f"Failed to insert security event: {errors}"
            )