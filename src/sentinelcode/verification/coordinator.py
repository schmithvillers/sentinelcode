from pathlib import Path

from sentinelcode.models.security_event import SecurityEvent
from sentinelcode.models.threat_event import ThreatEvent
from sentinelcode.security.security_orchestrator import SecurityOrchestrator
from sentinelcode.verification.models import (
    VerificationCheck,
    VerificationResult,
    VerificationStatus,
)
from sentinelcode.verification.pipeline import VerificationPipeline
from sentinelcode.verification.report import (
    VerificationReport,
    VerificationReportBuilder,
)


class VerificationCoordinator:
    """
    Coordinates security analysis and code verification.
    """

    def __init__(
        self,
        verification_pipeline: VerificationPipeline | None = None,
        security_orchestrator: SecurityOrchestrator | None = None,
    ) -> None:
        self.verification_pipeline = (
            verification_pipeline or VerificationPipeline()
        )
        self.security_orchestrator = security_orchestrator

    def verify(
        self,
        project_path: str | Path,
        events: list[SecurityEvent] | None = None,
    ) -> VerificationReport:
        """
        Run code verification and optionally analyze security events.
        """

        result = self.verification_pipeline.verify(project_path)

        threats: list[ThreatEvent] = []

        if (
            self.security_orchestrator is not None
            and events
        ):
            threats = self.security_orchestrator.analyze_events(
                events
            )

        result = self._add_security_result(
            result,
            threats,
        )

        return VerificationReportBuilder.build(result)

    @staticmethod
    def _add_security_result(
        result: VerificationResult,
        threats: list[ThreatEvent],
    ) -> VerificationResult:
        """
        Convert security threats into a verification check.
        """

        if not threats:
            return result

        findings = []

        for threat in threats:
            findings.append(
                {
                    "severity": threat.severity,
                    "message": threat.reason,
                    "identifier": threat.threat_type,
                }
            )

        security_check = VerificationCheck(
            name="security",
            status=VerificationStatus.FAIL,
            message=(
                f"Security analysis detected "
                f"{len(threats)} threat(s)"
            ),
            findings=findings,
        )

        checks = result.checks.copy()
        checks.append(security_check)

        if result.status == VerificationStatus.ERROR:
            final_status = VerificationStatus.ERROR
        else:
            final_status = VerificationStatus.FAIL

        return VerificationResult(
            status=final_status,
            checks=checks,
        )