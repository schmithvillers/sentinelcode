import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from sentinelcode.verification.models import (
    VerificationCheck,
    VerificationStatus,
)


class SASTVerifier:
    """Runs static application security testing using Bandit."""
    @staticmethod
    def _is_blocking_severity(severity: str | None) -> bool:
        return severity in {"MEDIUM", "HIGH", "CRITICAL"}
    def verify(self, project_path: str | Path) -> VerificationCheck:
        project = Path(project_path)

        if not project.exists():
            return VerificationCheck(
                name="sast",
                status=VerificationStatus.ERROR,
                message=f"Project path does not exist: {project}",
            )

        start = time.perf_counter()

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "bandit",
                    "-r",
                    str(project),
                    "-x",
                    str(project / "tests"),
                    "-f",
                    "json",
                    "-q",
                ],
                capture_output=True,
                text=True,
                cwd=project,
            )

            duration = time.perf_counter() - start

            findings = self._parse_findings(result.stdout)

            # Bandit returns exit code 1 when it finds
            # security issues. Exit code 0 means no issues.
            if result.returncode == 0:
                return VerificationCheck(
                    name="sast",
                    status=VerificationStatus.PASS,
                    message="No Bandit security findings",
                    findings=findings,
                    duration_seconds=duration,
                )

            if result.returncode == 1:
                blocking_findings = [
                    finding
                    for finding in findings
                    if self._is_blocking_severity(finding.get("severity"))
                ]

                if blocking_findings:
                    return VerificationCheck(
                        name="sast",
                        status=VerificationStatus.FAIL,
                        message=(
                            f"Bandit found {len(findings)} security finding(s), "
                            f"including {len(blocking_findings)} blocking finding(s)"
                        ),
                        findings=findings,
                        duration_seconds=duration,
                    )

                return VerificationCheck(
                    name="sast",
                    status=VerificationStatus.PASS,
                    message=(
                        f"Bandit found {len(findings)} low-severity finding(s); "
                        "none are blocking"
                    ),
                    findings=findings,
                    duration_seconds=duration,
                )

            return VerificationCheck(
                name="sast",
                status=VerificationStatus.ERROR,
                message=(
                    result.stderr.strip()
                    or "Bandit execution failed"
                ),
                findings=findings,
                duration_seconds=duration,
            )

        except OSError as exc:
            duration = time.perf_counter() - start

            return VerificationCheck(
                name="sast",
                status=VerificationStatus.ERROR,
                message=f"Unable to run Bandit: {exc}",
                duration_seconds=duration,
            )

    @staticmethod
    def _parse_findings(output: str) -> list[dict[str, Any]]:
        if not output.strip():
            return []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []

        findings = []

        for result in data.get("results", []):
            findings.append(
                {
                    "test_id": result.get("test_id"),
                    "test_name": result.get("test_name"),
                    "severity": result.get("issue_severity"),
                    "confidence": result.get("issue_confidence"),
                    "message": result.get("issue_text"),
                    "file": result.get("filename"),
                    "line": result.get("line_number"),
                    "line_range": result.get("line_range"),
                    "code": result.get("code"),
                }
            )

        return findings