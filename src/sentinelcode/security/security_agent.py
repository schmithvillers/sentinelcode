import json
from datetime import datetime, timezone

from sentinelcode.intelligence.gemini_client import GeminiClient
from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.models.threat_event import ThreatEvent


class SecurityAgent:
    """
    Uses Gemini to analyze SentinelCode security events
    and identify potentially malicious behavior.
    """

    def __init__(self, gemini_client: GeminiClient):
        self.gemini_client = gemini_client

    def analyze_event(
        self,
        event: SecurityEvent,
    ) -> ThreatEvent | None:
        """
        Analyze a single security event using Gemini.
        """

        prompt = self._build_event_prompt(event)

        response = self.gemini_client.analyze(prompt)

        analysis = self._parse_response(response)

        if not analysis.get("is_threat", False):
            return None

        return ThreatEvent(
            threat_type=analysis.get(
                "threat_type",
                "unknown",
            ),
            severity=analysis.get(
                "severity",
                "medium",
            ),
            reason=analysis.get(
                "reason",
                "Gemini identified suspicious behavior.",
            ),
            detected_at=datetime.now(timezone.utc),
            related_events=[event],
        )

    def _build_event_prompt(
        self,
        event: SecurityEvent,
    ) -> str:
        """
        Build a structured security-analysis prompt.
        """

        return f"""
You are the SentinelCode Security Agent.

Analyze the following security event from an autonomous
coding agent.

Determine whether the event represents suspicious or
malicious behavior.

Security event:

{{
    "event_id": "{event.event_id}",
    "timestamp": "{event.timestamp.isoformat()}",
    "agent": "{event.agent}",
    "tool": "{event.tool}",
    "action": "{event.action}",
    "resource": "{event.resource}",
    "decision": "{event.decision}",
    "risk_score": {event.risk_score},
    "reason": "{event.reason}"
}}

Return ONLY valid JSON with exactly these fields:

{{
    "is_threat": true,
    "threat_type": "credential_access",
    "severity": "high",
    "reason": "Brief explanation"
}}

If the event is safe, return:

{{
    "is_threat": false,
    "threat_type": "none",
    "severity": "low",
    "reason": "Brief explanation"
}}

Do not include markdown or additional text.
"""

    @staticmethod
    def _parse_response(
        response: str,
    ) -> dict:
        """
        Parse Gemini's JSON response.
        """

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return {
                "is_threat": False,
                "threat_type": "invalid_response",
                "severity": "low",
                "reason": (
                    "Gemini returned an invalid security analysis."
                ),
            }