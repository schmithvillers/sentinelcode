from pathlib import Path

from sentinelcode.verification.compiler import CompilerVerifier
from sentinelcode.verification.models import (
    VerificationCheck,
    VerificationResult,
    VerificationStatus,
)
from sentinelcode.verification.sast import SASTVerifier
from sentinelcode.verification.secrets import SecretScanner
from sentinelcode.verification.tests_runner import TestRunner


class VerificationPipeline:
    """Coordinates verification checks for a project."""

    def __init__(
        self,
        compiler: CompilerVerifier | None = None,
        test_runner: TestRunner | None = None,
        sast: SASTVerifier | None = None,
        secret_scanner: SecretScanner | None = None,
    ) -> None:
        self.compiler = compiler or CompilerVerifier()
        self.test_runner = test_runner or TestRunner()
        self.sast = sast or SASTVerifier()
        self.secret_scanner = secret_scanner or SecretScanner()

    def verify(self, project_path: str | Path) -> VerificationResult:
        checks: list[VerificationCheck] = []

        compile_check = self.compiler.verify(project_path)
        checks.append(compile_check)

        # Compilation is required before running tests.
        if compile_check.status != VerificationStatus.PASS:
            return self._build_result(checks)

        test_check = self.test_runner.verify(project_path)
        checks.append(test_check)

        # Security checks still run even when tests fail.
        sast_check = self.sast.verify(project_path)
        checks.append(sast_check)

        secret_check = self.secret_scanner.verify(project_path)
        checks.append(secret_check)

        return self._build_result(checks)

    @staticmethod
    def _build_result(
        checks: list[VerificationCheck],
    ) -> VerificationResult:
        if any(
            check.status == VerificationStatus.ERROR
            for check in checks
        ):
            status = VerificationStatus.ERROR
        elif any(
            check.status == VerificationStatus.FAIL
            for check in checks
        ):
            status = VerificationStatus.FAIL
        else:
            status = VerificationStatus.PASS

        return VerificationResult(
            status=status,
            checks=checks,
        )