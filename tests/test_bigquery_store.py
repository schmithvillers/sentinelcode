from sentinelcode.storage.bigquery_store import (
    BigQueryStore,
)
import pytest

from tests.helpers import (
    FakeBigQueryClient,
    create_security_event,
)


def test_security_event_is_inserted():

    client = FakeBigQueryClient()

    store = BigQueryStore(
        project_id="test-project",
        client=client,
    )

    event = create_security_event()

    store.insert_security_event(event)

    assert len(client.inserted_rows) == 1

    insertion = client.inserted_rows[0]

    assert (
        insertion["table"]
        == "test-project."
        "sentinelcode_security."
        "security_events"
    )

    rows = insertion["rows"]

    assert len(rows) == 1

    row = rows[0]

    assert row["event_id"] == "evt-001"
    assert row["agent"] == "coding-agent"
    assert row["tool"] == "filesystem"
    assert row["action"] == "read"
    assert row["resource"] == ".env"
    assert row["decision"] == "BLOCK"
    assert row["risk_score"] == 70
    assert row["reason"] == "Sensitive file access"
class FailingBigQueryClient:

    def insert_rows_json(
        self,
        table,
        rows,
    ):

        return [
            {
                "index": 0,
                "errors": [
                    {
                        "reason": "invalid",
                        "message": "Test failure",
                    }
                ],
            }
        ]
def test_bigquery_insert_failure_raises_error():

    client = FailingBigQueryClient()

    store = BigQueryStore(
        project_id="test-project",
        client=client,
    )

    event = create_security_event()

    with pytest.raises(RuntimeError):

        store.insert_security_event(event)