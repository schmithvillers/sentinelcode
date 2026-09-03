from pathlib import Path

from sentinelcode.verification.compiler import CompilerVerifier
from sentinelcode.verification.dependencies import DependencyScanner
from sentinelcode.verification.models import (
    VerificationCheck,
    VerificationStatus,
)
from sentinelcode.verification.pipeline import VerificationPipeline
from sentinelcode.verification.sast import SASTVerifier
from sentinelcode.verification.secrets import SecretScanner
from sentinelcode.verification.tests_runner import TestRunner


def create_project(
    tmp_path: Path,
    source: str,
    test_source: str,
) -> Path:
    project = tmp_path / "project"
    project.mkdir()

    (project / "main.py").write_text(
        source,
        encoding="utf-8",
    )

    tests_directory = project / "tests"
    tests_directory.mkdir()

    (tests_directory / "test_main.py").write_text(
        test_source,
        encoding="utf-8",
    )

    # Add a minimal dependency file so the dependency
    # scanner runs instead of returning SKIPPED.
    (project / "requirements.txt").write_text(
        "pytest\n",
        encoding="utf-8",
    )

    return project


def test_pipeline_passes_for_valid_project(tmp_path):
    project = create_project(
        tmp_path,
        """
def add(a, b):
    return a + b
""",
        """
from main import add


def test_add():
    assert add(2, 3) == 5
""",
    )

    pipeline = VerificationPipeline()

    result = pipeline.verify(project)

    assert result.status == VerificationStatus.PASS
    assert len(result.checks) == 5

    assert result.checks[0].name == "compile"
    assert result.checks[0].status == VerificationStatus.PASS

    assert result.checks[1].name == "tests"
    assert result.checks[1].status == VerificationStatus.PASS

    assert result.checks[2].name == "sast"
    assert result.checks[2].status == VerificationStatus.PASS

    assert result.checks[3].name == "secrets"
    assert result.checks[3].status == VerificationStatus.PASS

    assert result.checks[4].name == "dependencies"
    assert result.checks[4].status == VerificationStatus.PASS


def test_pipeline_fails_when_tests_fail(tmp_path):
    project = create_project(
        tmp_path,
        """
def add(a, b):
    return a + b
""",
        """
from main import add


def test_add():
    assert add(2, 3) == 999
""",
    )

    pipeline = VerificationPipeline()

    result = pipeline.verify(project)

    assert result.status == VerificationStatus.FAIL
    assert len(result.checks) == 5

    assert result.checks[0].status == VerificationStatus.PASS
    assert result.checks[1].status == VerificationStatus.FAIL
    assert result.checks[2].status == VerificationStatus.PASS
    assert result.checks[3].status == VerificationStatus.PASS
    assert result.checks[4].name == "dependencies"
    assert result.checks[4].status == VerificationStatus.PASS


def test_pipeline_fails_when_sast_finds_vulnerability(tmp_path):
    project = create_project(
        tmp_path,
        """
import subprocess


def run_command(user_input):
    subprocess.run(user_input, shell=True)
""",
        """
from main import run_command


def test_placeholder():
    assert True
""",
    )

    pipeline = VerificationPipeline()

    result = pipeline.verify(project)

    assert result.status == VerificationStatus.FAIL
    assert len(result.checks) == 5

    assert result.checks[0].status == VerificationStatus.PASS
    assert result.checks[1].status == VerificationStatus.PASS

    assert result.checks[2].name == "sast"
    assert result.checks[2].status == VerificationStatus.FAIL
    assert len(result.checks[2].findings) > 0

    assert result.checks[3].name == "secrets"
    assert result.checks[3].status == VerificationStatus.PASS

    assert result.checks[4].name == "dependencies"
    assert result.checks[4].status == VerificationStatus.PASS


def test_pipeline_stops_when_compilation_fails(tmp_path):
    project = create_project(
        tmp_path,
        """
def add(a, b)
    return a + b
""",
        """
def test_should_not_run():
    assert False
""",
    )

    pipeline = VerificationPipeline()

    result = pipeline.verify(project)

    assert result.status == VerificationStatus.FAIL
    assert len(result.checks) == 1

    assert result.checks[0].name == "compile"
    assert result.checks[0].status == VerificationStatus.FAIL


def test_pipeline_returns_error_for_missing_project(tmp_path):
    missing_project = tmp_path / "does-not-exist"

    pipeline = VerificationPipeline()

    result = pipeline.verify(missing_project)

    assert result.status == VerificationStatus.ERROR
    assert len(result.checks) == 1
    assert result.checks[0].status == VerificationStatus.ERROR


def test_pipeline_can_use_custom_verifiers(tmp_path):
    project = create_project(
        tmp_path,
        """
def add(a, b):
    return a + b
""",
        """
from main import add


def test_add():
    assert add(2, 3) == 5
""",
    )

    class FakeCompiler:
        def verify(self, project_path):
            return VerificationCheck(
                name="compile",
                status=VerificationStatus.PASS,
            )

    class FakeTestRunner:
        def verify(self, project_path):
            return VerificationCheck(
                name="tests",
                status=VerificationStatus.PASS,
            )

    class FakeSAST:
        def verify(self, project_path):
            return VerificationCheck(
                name="sast",
                status=VerificationStatus.PASS,
            )

    class FakeSecretScanner:
        def verify(self, project_path):
            return VerificationCheck(
                name="secrets",
                status=VerificationStatus.PASS,
            )

    class FakeDependencyScanner:
        def verify(self, project_path):
            return VerificationCheck(
                name="dependencies",
                status=VerificationStatus.PASS,
            )

    pipeline = VerificationPipeline(
        compiler=FakeCompiler(),
        test_runner=FakeTestRunner(),
        sast=FakeSAST(),
        secret_scanner=FakeSecretScanner(),
        dependency_scanner=FakeDependencyScanner(),
    )

    result = pipeline.verify(project)

    assert result.status == VerificationStatus.PASS
    assert len(result.checks) == 5


def test_pipeline_fails_when_secret_is_detected(tmp_path):
    project = create_project(
        tmp_path,
        """
def add(a, b):
    return a + b
""",
        """
def test_placeholder():
    assert True
""",
    )

    (project / "private_key.pem").write_text(
        """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB
AAAAC3NzaC1yc2EAAAADAQABAAABAQCfakeSentinelCodeTestKey
-----END OPENSSH PRIVATE KEY-----
""",
        encoding="utf-8",
    )

    pipeline = VerificationPipeline()

    result = pipeline.verify(project)

    assert result.status == VerificationStatus.FAIL
    assert len(result.checks) == 5

    assert result.checks[0].name == "compile"
    assert result.checks[0].status == VerificationStatus.PASS

    assert result.checks[1].name == "tests"
    assert result.checks[1].status == VerificationStatus.PASS

    assert result.checks[2].name == "sast"
    assert result.checks[2].status == VerificationStatus.PASS

    assert result.checks[3].name == "secrets"
    assert result.checks[3].status == VerificationStatus.FAIL

    assert result.checks[4].name == "dependencies"
    assert result.checks[4].status == VerificationStatus.PASS

    assert len(result.checks[3].findings) > 0

    finding = result.checks[3].findings[0]

    assert finding["secret"] == "[REDACTED]"
    assert finding["match"] == "[REDACTED]"


def test_pipeline_fails_when_dependency_is_vulnerable(tmp_path):
    project = create_project(
        tmp_path,
        """
def add(a, b):
    return a + b
""",
        """
from main import add


def test_add():
    assert add(2, 3) == 5
""",
    )

    class FakeDependencyScanner:
        def verify(self, project_path):
            return VerificationCheck(
                name="dependencies",
                status=VerificationStatus.FAIL,
                message="Dependency vulnerability detected",
                findings=[
                    {
                        "package": "requests",
                        "version": "2.19.0",
                        "id": "PYSEC-TEST-001",
                    }
                ],
            )

    pipeline = VerificationPipeline(
        dependency_scanner=FakeDependencyScanner(),
    )

    result = pipeline.verify(project)

    assert result.status == VerificationStatus.FAIL
    assert len(result.checks) == 5

    dependency_check = result.checks[4]

    assert dependency_check.name == "dependencies"
    assert dependency_check.status == VerificationStatus.FAIL
    assert len(dependency_check.findings) == 1