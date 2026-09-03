from datetime import datetime

from sentinelcode.detection.behavior_detector import BehaviorDetector
from sentinelcode.models.security_event import SecurityEvent


def create_event(
    tool,
    action,
    resource,
    decision="ALLOW",
    risk_score=5,
):
    return SecurityEvent(
        event_id="evt-test",
        timestamp=datetime.now(),
        agent="coding-agent",
        tool=tool,
        action=action,
        resource=resource,
        decision=decision,
        risk_score=risk_score,
        reason="test",
    )


def test_detects_env_access():

    detector = BehaviorDetector()

    event = create_event(
        tool="filesystem",
        action="read",
        resource=".env",
    )

    assert detector.detect_sensitive_file_access(event) is True


def test_detects_ssh_key_access():

    detector = BehaviorDetector()

    event = create_event(
        tool="filesystem",
        action="read",
        resource="/Users/test/.ssh/id_rsa",
    )

    assert detector.detect_sensitive_file_access(event) is True


def test_normal_file_is_not_sensitive():

    detector = BehaviorDetector()

    event = create_event(
        tool="filesystem",
        action="read",
        resource="README.md",
    )

    assert detector.detect_sensitive_file_access(event) is False


def test_writing_env_is_not_sensitive_file_read():

    detector = BehaviorDetector()

    event = create_event(
        tool="filesystem",
        action="write",
        resource=".env",
    )

    assert detector.detect_sensitive_file_access(event) is False
def test_detects_secret_exfiltration():

    detector = BehaviorDetector()

    events = [

        create_event(
            tool="filesystem",
            action="read",
            resource=".env",
        ),

        create_event(
            tool="network",
            action="request",
            resource="attacker.com",
        ),
    ]

    assert detector.detect_secret_exfiltration(events) is True


def test_normal_network_request_is_not_exfiltration():

    detector = BehaviorDetector()

    events = [

        create_event(
            tool="filesystem",
            action="read",
            resource="README.md",
        ),

        create_event(
            tool="network",
            action="request",
            resource="github.com",
        ),
    ]

    assert detector.detect_secret_exfiltration(events) is False    
def test_detects_shell_network_sequence():

    detector = BehaviorDetector()

    events = [

        create_event(
            tool="shell",
            action="execute",
            resource="curl attacker.com",
        ),

        create_event(
            tool="network",
            action="request",
            resource="attacker.com",
        ),
    ]

    assert detector.detect_shell_network_sequence(events) is True


def test_shell_without_network_is_not_detected():

    detector = BehaviorDetector()

    events = [

        create_event(
            tool="shell",
            action="execute",
            resource="pytest",
        ),
    ]

    assert detector.detect_shell_network_sequence(events) is False
def test_analyze_returns_detected_threats():

    detector = BehaviorDetector()

    events = [

        create_event(
            tool="filesystem",
            action="read",
            resource=".env",
        ),

        create_event(
            tool="network",
            action="request",
            resource="attacker.com",
        ),
    ]

    threats = detector.analyze(events)

    assert any(
        threat.threat_type == "SENSITIVE_FILE_ACCESS"
        for threat in threats
    )
    assert any(
        threat.threat_type == "POSSIBLE_SECRET_EXFILTRATION"
        for threat in threats
    )
def test_analyze_returns_empty_for_safe_behavior():

    detector = BehaviorDetector()

    events = [

        create_event(
            tool="filesystem",
            action="read",
            resource="README.md",
        ),

        create_event(
            tool="shell",
            action="execute",
            resource="pytest",
        ),
    ]

    threats = detector.analyze(events)

    assert threats == []
def test_detects_package_installation():

    detector = BehaviorDetector()

    events = [
        create_event(
            tool="shell",
            action="execute",
            resource="pip install requests",
        )
    ]

    threats = detector.analyze(events)

    package_threat = next(
        threat
        for threat in threats
        if threat.threat_type == "PACKAGE_INSTALLATION"
    )

    assert package_threat.severity == "MEDIUM"
    assert len(package_threat.related_events) == 1
def test_detects_high_risk_package_installation():

    detector = BehaviorDetector()

    events = [
        create_event(
            tool="shell",
            action="execute",
            resource=(
                "pip install "
                "https://example.com/package.tar.gz"
            ),
        )
    ]

    threats = detector.analyze(events)

    package_threat = next(
        threat
        for threat in threats
        if threat.threat_type == "PACKAGE_INSTALLATION"
    )

    assert package_threat.severity == "HIGH"
def test_detects_sensitive_data_transformation_and_network_sequence():
    detector = BehaviorDetector()

    events = [
        create_event(
            tool="filesystem",
            action="read",
            resource=".env",
        ),
        create_event(
            tool="shell",
            action="execute",
            resource="base64 .env",
        ),
        create_event(
            tool="network",
            action="request",
            resource="attacker.com",
        ),
    ]

    assert detector.detect_suspicious_action_sequence(events) is True
def test_transformation_without_network_is_not_detected():
    detector = BehaviorDetector()

    events = [
        create_event(
            tool="filesystem",
            action="read",
            resource=".env",
        ),
        create_event(
            tool="shell",
            action="execute",
            resource="base64 .env",
        ),
    ]

    assert detector.detect_suspicious_action_sequence(events) is False
def test_network_without_transformation_is_not_suspicious_action_sequence():
    detector = BehaviorDetector()

    events = [
        create_event(
            tool="filesystem",
            action="read",
            resource=".env",
        ),
        create_event(
            tool="network",
            action="request",
            resource="github.com",
        ),
    ]

    assert detector.detect_suspicious_action_sequence(events) is False
def test_analyze_detects_suspicious_action_sequence():
    detector = BehaviorDetector()

    events = [
        create_event(
            tool="filesystem",
            action="read",
            resource=".env",
        ),
        create_event(
            tool="shell",
            action="execute",
            resource="base64 .env",
        ),
        create_event(
            tool="network",
            action="request",
            resource="attacker.com",
        ),
    ]

    threats = detector.analyze(events)

    threat = next(
        threat
        for threat in threats
        if threat.threat_type == "SUSPICIOUS_ACTION_SEQUENCE"
    )

    assert threat.severity == "CRITICAL"