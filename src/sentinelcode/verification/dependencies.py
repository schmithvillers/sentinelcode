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


class DependencyScanner:
    """Scans Python dependencies for known vulnerabilities."""

    def verify(
        self,
        project_path: str | Path,
    ) -> VerificationCheck:
        project = Path(project_path)

        if not project.exists():
            return VerificationCheck(
                name="dependencies",
                status=VerificationStatus.ERROR,
                message=f"Project path does not exist: {project}",
            )

        requirements = project / "requirements.txt"

        if not requirements.exists():
            return VerificationCheck(
                name="dependencies",
                status=VerificationStatus.SKIPPED,
                message="No requirements.txt found",
            )

        start = time.perf_counter()

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip_audit",
                    "-r",
                    str(requirements),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                cwd=project,
            )

            duration = time.perf_counter() - start

            findings = self._parse_findings(result.stdout)

            if result.returncode == 0:
                return VerificationCheck(
                    name="dependencies",
                    status=VerificationStatus.PASS,
                    message="No known dependency vulnerabilities detected",
                    findings=findings,
                    duration_seconds=duration,
                )

            if result.returncode == 1:
                return VerificationCheck(
                    name="dependencies",
                    status=VerificationStatus.FAIL,
                    message=(
                        f"Dependency scanner found "
                        f"{len(findings)} vulnerable package(s)"
                    ),
                    findings=findings,
                    duration_seconds=duration,
                )

            return VerificationCheck(
                name="dependencies",
                status=VerificationStatus.ERROR,
                message=(
                    result.stderr.strip()
                    or "Dependency scanner execution failed"
                ),
                findings=findings,
                duration_seconds=duration,
            )

        except OSError as exc:
            duration = time.perf_counter() - start

            return VerificationCheck(
                name="dependencies",
                status=VerificationStatus.ERROR,
                message=f"Unable to run dependency scanner: {exc}",
                duration_seconds=duration,
            )

    @staticmethod
    def _parse_findings(
        output: str,
    ) -> list[dict[str, Any]]:
        if not output.strip():
            return []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []

        findings = []

        for vulnerability in data:
            if not isinstance(vulnerability, dict):
                continue

            findings.append(
                {
                    "package": vulnerability.get("name"),
                    "version": vulnerability.get("version"),
                    "id": vulnerability.get("id"),
                    "description": vulnerability.get(
                        "description"
                    ),
                    "fix_versions": vulnerability.get(
                        "fix_versions",
                        [],
                    ),
                }
            )

        return findings