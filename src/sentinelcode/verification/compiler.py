import subprocess
import sys
import time
from pathlib import Path

from sentinelcode.verification.models import (
    VerificationCheck,
    VerificationStatus,
)


class CompilerVerifier:
    """Verifies that Python source files can be compiled."""

    def verify(self, project_path: str | Path) -> VerificationCheck:
        project = Path(project_path)

        if not project.exists():
            return VerificationCheck(
                name="compile",
                status=VerificationStatus.ERROR,
                message=f"Project path does not exist: {project}",
            )

        start = time.perf_counter()

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "compileall",
                    "-q",
                    str(project),
                ],
                capture_output=True,
                text=True,
                cwd=project,
            )

            duration = time.perf_counter() - start

            if result.returncode == 0:
                return VerificationCheck(
                    name="compile",
                    status=VerificationStatus.PASS,
                    message="Python compilation succeeded",
                    duration_seconds=duration,
                )

            return VerificationCheck(
                name="compile",
                status=VerificationStatus.FAIL,
                message=result.stderr.strip()
                or "Python compilation failed",
                duration_seconds=duration,
            )

        except OSError as exc:
            duration = time.perf_counter() - start

            return VerificationCheck(
                name="compile",
                status=VerificationStatus.ERROR,
                message=f"Unable to run compiler: {exc}",
                duration_seconds=duration,
            )