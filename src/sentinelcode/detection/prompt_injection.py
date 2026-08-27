from datetime import datetime

from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.models.threat_event import ThreatEvent


class PromptInjectionDetector:
    """
    Detects obvious prompt-injection patterns in untrusted content.
    """

    SUSPICIOUS_PATTERNS = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "ignore prior instructions",
        "disregard previous instructions",
        "disregard all previous instructions",
        "system instruction",
        "you are now",
        "send the following",
        "upload",
        "exfiltrate",
    ]

    def contains_injection(self, content: str) -> bool:
        """
        Return True when suspicious prompt-injection
        language is detected.
        """

        normalized = content.lower()

        return any(
            pattern in normalized
            for pattern in self.SUSPICIOUS_PATTERNS
        )

    def analyze(
        self,
        content: str,
        source: str
    ) -> ThreatEvent | None:
        """
        Analyze untrusted content and return a ThreatEvent
        when prompt injection is detected.
        """

        if not self.contains_injection(content):
            return None

        return ThreatEvent(
            threat_type="PROMPT_INJECTION",
            severity="HIGH",
            reason=(
                f"Potential prompt injection detected "
                f"in untrusted content from {source}."
            ),
            detected_at=datetime.now(),
            related_events=[],
        )