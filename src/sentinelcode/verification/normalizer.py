from typing import Any

from sentinelcode.verification.models import VerificationFinding


class FindingNormalizer:
    """Converts scanner-specific findings into a common format."""

    @staticmethod
    def normalize_check(
        scanner: str,
        findings: list[dict[str, Any]],
    ) -> list[VerificationFinding]:
        normalized = []

        for finding in findings:
            normalized.append(
                FindingNormalizer.normalize(
                    scanner,
                    finding,
                )
            )

        return normalized

    @staticmethod
    def normalize(
        scanner: str,
        finding: dict[str, Any],
    ) -> VerificationFinding:
        scanner = scanner.lower()

        if scanner in {"bandit", "sast"}:
            return VerificationFinding(
                scanner=scanner,
                finding_type="SAST",
                severity=finding.get("severity") or "UNKNOWN",
                message=(
                    finding.get("message")
                    or "Bandit security finding"
                ),
                file=finding.get("file"),
                line=finding.get("line"),
                identifier=finding.get("test_id"),
            )

        if scanner in {"gitleaks", "secrets"}:
            return VerificationFinding(
                scanner=scanner,
                finding_type="SECRET",
                severity=finding.get("severity") or "HIGH",
                message=(
                    finding.get("description")
                    or finding.get("message")
                    or "Potential secret detected"
                ),
                file=finding.get("file"),
                line=finding.get("line"),
                identifier=finding.get("rule_id"),
            )

        if scanner in {"pip-audit", "dependencies"}:
            return VerificationFinding(
                scanner=scanner,
                finding_type="DEPENDENCY",
                severity=finding.get("severity") or "HIGH",
                message=(
                    finding.get("description")
                    or finding.get("message")
                    or "Dependency vulnerability detected"
                ),
                package=finding.get("package"),
                version=finding.get("version"),
                identifier=finding.get("id"),
            )

        if scanner == "security":
            return VerificationFinding(
                scanner="security",
                finding_type="SECURITY",
                severity=finding.get("severity") or "UNKNOWN",
                message=(
                    finding.get("message")
                    or "Security threat detected"
                ),
                identifier=finding.get("identifier"),
            )

        return VerificationFinding(
            scanner=scanner,
            finding_type="UNKNOWN",
            severity="UNKNOWN",
            message=str(
                finding.get(
                    "message",
                    "Unknown verification finding",
                )
            ),
        )