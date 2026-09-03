from sentinelcode.detection.behavior_detector import BehaviorDetector
from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.models.threat_event import ThreatEvent
from sentinelcode.security.security_agent import SecurityAgent


class SecurityOrchestrator:
    """
    Coordinates deterministic behavior detection and
    contextual security analysis.
    """

    def __init__(
        self,
        security_agent: SecurityAgent,
        behavior_detector: BehaviorDetector | None = None,
    ) -> None:
        self.security_agent = security_agent
        self.behavior_detector = behavior_detector or BehaviorDetector()

    def analyze_event(
        self,
        event: SecurityEvent,
    ) -> list[ThreatEvent]:
        """
        Analyze a single security event.

        Gemini is used for contextual analysis.
        """

        contextual_threat = self.security_agent.analyze_event(event)

        if contextual_threat is None:
            return []

        return [contextual_threat]

    def analyze_events(
        self,
        events: list[SecurityEvent],
    ) -> list[ThreatEvent]:
        """
        Analyze a sequence of security events.

        This path uses deterministic behavior detection.
        Gemini is intentionally not called here.
        """

        return self.behavior_detector.analyze(events)