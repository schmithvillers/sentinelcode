from sentinelcode.models.security_event import SecurityEvent
from datetime import datetime

from sentinelcode.models.threat_event import ThreatEvent
from sentinelcode.detection.package_detector import ( PackageInstallationDetector,)
class BehaviorDetector:
    """
    Detects suspicious behavior across multiple security events.
    """

    SENSITIVE_FILES = {
        ".env",
        ".env.local",
        "id_rsa",
        "id_ed25519",
        "credentials",
        "credentials.json",
        "secrets.json",
    }
    THREAT_SEVERITY = {
        "SENSITIVE_FILE_ACCESS": "HIGH",
        "POSSIBLE_SECRET_EXFILTRATION": "CRITICAL",
        "SUSPICIOUS_SHELL_NETWORK_ACTIVITY": "HIGH",
        "SUSPICIOUS_ACTION_SEQUENCE": "CRITICAL",
    }
    def __init__(self):
        self.package_detector = PackageInstallationDetector()

    def detect_sensitive_file_access( self, event: SecurityEvent ) -> bool:
        """
        Detect access to known sensitive files.
        """

        if event.tool != "filesystem":
            return False

        if event.action != "read":
            return False

        resource = event.resource

        return any(
            resource.endswith(filename)
            for filename in self.SENSITIVE_FILES
        )

    def detect_secret_exfiltration( self, events: list[SecurityEvent] ) -> bool:
        """
        Detect sensitive file access followed by network activity.
        """

        sensitive_access = False

        for event in events:

            if self.detect_sensitive_file_access(event):
                sensitive_access = True
                continue

            if sensitive_access and event.tool == "network":
                return True

        return False

    def detect_shell_network_sequence(
        self,
        events: list[SecurityEvent]
    ) -> bool:
        """
        Detect shell execution followed by network activity.
        """

        shell_activity = False

        for event in events:

            if event.tool == "shell":
                shell_activity = True
                continue

            if shell_activity and event.tool == "network":
                return True

        return False
    
    def detect_suspicious_action_sequence( self, events: list[SecurityEvent], ) -> bool:
        """
        Detect sensitive data being transformed before
        network activity.
        """

        sensitive_access = False
        transformation = False

        for event in events:

            if self.detect_sensitive_file_access(event):
                sensitive_access = True
                continue

            if not sensitive_access:
                continue

            if event.tool == "shell" and any(
                keyword in event.resource.lower()
                for keyword in (
                    "base64",
                    "encode",
                    "encrypt",
                    "gzip",
                    "compress",
                )
            ):
                transformation = True
                continue

            if transformation and event.tool == "network":
                return True

        return False

    def analyze( self, events: list[SecurityEvent]) -> list[ThreatEvent]:

        threats = []

        # Detect sensitive file access
        if any(
            self.detect_sensitive_file_access(event)
            for event in events
        ):
            threats.append(
                ThreatEvent(
                    threat_type="SENSITIVE_FILE_ACCESS",
                    severity=self.THREAT_SEVERITY[
                        "SENSITIVE_FILE_ACCESS"
                    ],
                    reason="Agent accessed a sensitive file.",
                    detected_at=datetime.now(),
                    related_events=events,
                )
            )

        # Detect sensitive file access followed by network activity
        if self.detect_secret_exfiltration(events):
            threats.append(
                ThreatEvent(
                    threat_type="POSSIBLE_SECRET_EXFILTRATION",
                    severity=self.THREAT_SEVERITY[
                        "POSSIBLE_SECRET_EXFILTRATION"
                    ],
                    reason=(
                        "Sensitive file access was followed "
                        "by network activity."
                    ),
                    detected_at=datetime.now(),
                    related_events=events,
                )
            )

        # Detect shell activity followed by network activity
        if self.detect_shell_network_sequence(events):
            threats.append(
                ThreatEvent(
                    threat_type="SUSPICIOUS_SHELL_NETWORK_ACTIVITY",
                    severity=self.THREAT_SEVERITY[
                        "SUSPICIOUS_SHELL_NETWORK_ACTIVITY"
                    ],
                    reason=(
                        "Shell activity was followed "
                        "by network activity."
                    ),
                    detected_at=datetime.now(),
                    related_events=events,
                )
            )
        # Detect sensitive data transformation followed by network activity
        if self.detect_suspicious_action_sequence(events):
            threats.append(
                ThreatEvent(
                    threat_type="SUSPICIOUS_ACTION_SEQUENCE",
                    severity=self.THREAT_SEVERITY[
                        "SUSPICIOUS_ACTION_SEQUENCE"
                    ],
                    reason=(
                        "Sensitive file access was followed "
                        "by data transformation and network activity."
                    ),
                    detected_at=datetime.now(),
                    related_events=events,
                )
            )
        # Detect package installations
        for event in events:

            if event.tool != "shell":
                continue

            if event.action != "execute":
                continue

            threat = self.package_detector.analyze(
                event.resource,
                source="agent-shell",
            )

            if threat is not None:
                threat.related_events = [event]
                threats.append(threat)

        return threats