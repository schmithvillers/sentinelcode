import subprocess
import sys
import time
from pathlib import Path

from sentinelcode.verification.models import (
    VerificationCheck,
    VerificationStatus,
)


class TestRunner:
    """Runs a project's pytest test suite."""

    def verify(self, project_path: str | Path) -> VerificationCheck:
        project = Path(project_path)

        if not project.exists():
            return VerificationCheck(
                name="tests",
                status=VerificationStatus.ERROR,
                message=f"Project path does not exist: {project}",
            )

        start = time.perf_counter()

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                ],
                capture_output=True,
                text=True,
                cwd=project,
            )

            duration = time.perf_counter() - start

            if result.returncode == 0:
                return VerificationCheck(
                    name="tests",
                    status=VerificationStatus.PASS,
                    message=self._success_message(result.stdout),
                    duration_seconds=duration,
                )

            return VerificationCheck(
                name="tests",
                status=VerificationStatus.FAIL,
                message=self._failure_message(
                    result.stdout,
                    result.stderr,
                ),
                duration_seconds=duration,
            )

        except OSError as exc:
            duration = time.perf_counter() - start

            return VerificationCheck(
                name="tests",
                status=VerificationStatus.ERROR,
                message=f"Unable to run tests: {exc}",
                duration_seconds=duration,
            )

    @staticmethod
    def _success_message(stdout: str) -> str:
        output = stdout.strip()

        if output:
            return f"Test suite passed: {output}"

        return "Test suite passed"

    @staticmethod
    def _failure_message(stdout: str, stderr: str) -> str:
        output = stdout.strip()

        if output:
            return f"Test suite failed: {output}"

        error = stderr.strip()

        if error:
            return f"Test runner error: {error}"

        return "Test suite failed"