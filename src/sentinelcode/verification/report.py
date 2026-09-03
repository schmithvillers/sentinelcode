from dataclasses import dataclass, field

from sentinelcode.verification.models import (
    VerificationCheck,
    VerificationFinding,
    VerificationResult,
    VerificationStatus,
)
from sentinelcode.verification.normalizer import FindingNormalizer


@dataclass
class VerificationReport:
    """Human-readable verification report."""

    status: VerificationStatus
    checks: list[VerificationCheck] = field(default_factory=list)
    findings: list[VerificationFinding] = field(
        default_factory=list
    )

    @property
    def passed(self) -> bool:
        return self.status == VerificationStatus.PASS

    @property
    def failed(self) -> bool:
        return self.status == VerificationStatus.FAIL

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def to_text(self) -> str:
        """Render the report as human-readable text."""

        lines = [
            "SENTINELCODE VERIFICATION REPORT",
            "================================",
            "",
            f"Status: {self.status.value}",
            "",
            "Checks:",
        ]

        for check in self.checks:
            symbol = self._status_symbol(check.status)

            lines.append(
                f"{symbol} {check.name:<14} "
                f"{check.status.value}"
            )

        lines.extend(
            [
                "",
                f"Security Findings: {self.total_findings}",
            ]
        )

        for index, finding in enumerate(
            self.findings,
            start=1,
        ):
            lines.extend(
                [
                    "",
                    (
                        f"{index}. "
                        f"[{finding.severity}] "
                        f"{finding.finding_type}"
                    ),
                    f"   {finding.message}",
                ]
            )

            if finding.file is not None:
                location = finding.file

                if finding.line is not None:
                    location += f":{finding.line}"

                lines.append(f"   File: {location}")

            if finding.package is not None:
                package = finding.package

                if finding.version is not None:
                    package += f"=={finding.version}"

                lines.append(
                    f"   Package: {package}"
                )

            if finding.identifier is not None:
                lines.append(
                    f"   ID: {finding.identifier}"
                )

        return "\n".join(lines)

    @staticmethod
    def _status_symbol(
        status: VerificationStatus,
    ) -> str:
        if status == VerificationStatus.PASS:
            return "✓"

        if status == VerificationStatus.FAIL:
            return "✗"

        if status == VerificationStatus.ERROR:
            return "!"

        return "-"


class VerificationReportBuilder:
    """Builds a report from a VerificationResult."""

    @staticmethod
    def build(
        result: VerificationResult,
    ) -> VerificationReport:
        findings: list[VerificationFinding] = []

        for check in result.checks:
            if not check.findings:
                continue

            normalized = FindingNormalizer.normalize_check(
                check.name,
                check.findings,
            )

            findings.extend(normalized)

        return VerificationReport(
            status=result.status,
            checks=result.checks,
            findings=findings,
        )