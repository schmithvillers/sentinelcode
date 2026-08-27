import json

from google.cloud import pubsub_v1

from sentinelcode.events.event_bus import EventBus
from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.models.threat_event import ThreatEvent


class PubSubEventBus(EventBus):
    """
    Google Cloud Pub/Sub implementation of the SentinelCode EventBus.
    """

    def __init__(
        self,
        project_id: str,
        security_topic: str = "sentinel-security-events",
        threat_topic: str = "sentinel-threat-events",
        publisher=None,
    ):
        self.project_id = project_id

        self.security_topic_path = (
            f"projects/{project_id}/topics/{security_topic}"
        )

        self.threat_topic_path = (
            f"projects/{project_id}/topics/{threat_topic}"
        )

        self.publisher = (
            publisher
            if publisher is not None
            else pubsub_v1.PublisherClient()
        )

    def publish_security_event(
        self,
        event: SecurityEvent,
    ) -> None:

        payload = self._serialize_security_event(event)

        future = self.publisher.publish(
            self.security_topic_path,
            payload,
        )

        future.result()

    def publish_threat_event(
        self,
        threat: ThreatEvent,
    ) -> None:

        payload = self._serialize_threat_event(threat)

        future = self.publisher.publish(
            self.threat_topic_path,
            payload,
        )

        future.result()

    def _serialize_security_event(
        self,
        event: SecurityEvent,
    ) -> bytes:

        data = {
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

        return json.dumps(data).encode("utf-8")

    def _serialize_threat_event(
        self,
        threat: ThreatEvent,
    ) -> bytes:

        data = {
            "threat_type": threat.threat_type,
            "severity": threat.severity,
            "reason": threat.reason,
            "detected_at": threat.detected_at.isoformat(),
            "related_event_ids": [
                event.event_id
                for event in threat.related_events
            ],
        }

        return json.dumps(data).encode("utf-8")