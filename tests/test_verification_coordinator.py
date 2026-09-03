from datetime import datetime
from unittest.mock import MagicMock

from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.models.threat_event import ThreatEvent
from sentinelcode.verification.coordinator import VerificationCoordinator
from sentinelcode.verification.models import (
    VerificationCheck,
    VerificationResult,
    VerificationStatus,
)


def make_event(**overrides):
    values = {
        "event_id": "event-123",
        "timestamp": datetime.now(),
        "agent": "coding-agent",
        "tool": "filesystem",
        "action": "read",
        "resource": ".env",
        "decision": "BLOCK",
        "risk_score": 70,
        "reason": "Policy violation",
    }

    values.update(overrides)

    return SecurityEvent(**values)


def make_threat(event=None):
    if event is None:
        event = make_event()

    return ThreatEvent(
        threat_type="SENSITIVE_FILE_ACCESS",
        severity="HIGH",
        reason="Agent accessed a sensitive file.",
        detected_at=event.timestamp,
        related_events=[event],
    )


def make_result(
    status=VerificationStatus.PASS,
    findings=None,
):
    check = VerificationCheck(
        name="tests",
        status=status,
        message="Verification completed.",
        findings=findings or [],
    )

    return VerificationResult(
        status=status,
        checks=[check],
    )


def test_coordinator_returns_passing_report_when_everything_is_safe():
    pipeline = MagicMock()
    pipeline.verify.return_value = make_result()

    coordinator = VerificationCoordinator(
        verification_pipeline=pipeline,
    )

    report = coordinator.verify("/tmp/project")

    assert report.status == VerificationStatus.PASS
    assert report.passed is True
    assert report.failed is False
    assert report.total_findings == 0

    pipeline.verify.assert_called_once_with("/tmp/project")


def test_coordinator_runs_security_analysis_when_events_exist():
    pipeline = MagicMock()
    pipeline.verify.return_value = make_result()

    orchestrator = MagicMock()

    event = make_event()
    threat = make_threat(event)

    orchestrator.analyze_events.return_value = [threat]

    coordinator = VerificationCoordinator(
        verification_pipeline=pipeline,
        security_orchestrator=orchestrator,
    )

    report = coordinator.verify(
        "/tmp/project",
        events=[event],
    )

    assert report.status == VerificationStatus.FAIL
    assert report.failed is True

    assert report.total_findings == 1

    finding = report.findings[0]

    assert finding.scanner == "security"
    assert finding.finding_type == "SECURITY"
    assert finding.severity == "HIGH"
    assert finding.message == "Agent accessed a sensitive file."
    assert finding.identifier == "SENSITIVE_FILE_ACCESS"

    orchestrator.analyze_events.assert_called_once_with([event])


def test_coordinator_adds_security_check_to_report():
    pipeline = MagicMock()
    pipeline.verify.return_value = make_result()

    orchestrator = MagicMock()

    event = make_event()
    threat = make_threat(event)

    orchestrator.analyze_events.return_value = [threat]

    coordinator = VerificationCoordinator(
        verification_pipeline=pipeline,
        security_orchestrator=orchestrator,
    )

    report = coordinator.verify(
        "/tmp/project",
        events=[event],
    )

    assert len(report.checks) == 2

    security_check = report.checks[-1]

    assert security_check.name == "security"
    assert security_check.status == VerificationStatus.FAIL
    assert security_check.message == "Security analysis detected 1 threat(s)"
    assert len(security_check.findings) == 1


def test_coordinator_preserves_verification_failure():
    pipeline = MagicMock()
    pipeline.verify.return_value = make_result(
        status=VerificationStatus.FAIL,
    )

    coordinator = VerificationCoordinator(
        verification_pipeline=pipeline,
    )

    report = coordinator.verify("/tmp/project")

    assert report.status == VerificationStatus.FAIL
    assert report.failed is True

    assert len(report.checks) == 1
    assert report.checks[0].status == VerificationStatus.FAIL


def test_coordinator_preserves_error_status():
    pipeline = MagicMock()
    pipeline.verify.return_value = make_result(
        status=VerificationStatus.ERROR,
    )

    orchestrator = MagicMock()

    event = make_event()
    threat = make_threat(event)

    orchestrator.analyze_events.return_value = [threat]

    coordinator = VerificationCoordinator(
        verification_pipeline=pipeline,
        security_orchestrator=orchestrator,
    )

    report = coordinator.verify(
        "/tmp/project",
        events=[event],
    )

    assert report.status == VerificationStatus.ERROR
    assert report.failed is False
    assert report.passed is False

    assert len(report.checks) == 2
    assert report.checks[0].status == VerificationStatus.ERROR
    assert report.checks[1].status == VerificationStatus.FAIL