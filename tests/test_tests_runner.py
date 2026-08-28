from pathlib import Path

from sentinelcode.verification.models import VerificationStatus
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

    return project


def test_runner_passes_when_tests_pass(tmp_path):
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

    runner = TestRunner()

    result = runner.verify(project)

    assert result.name == "tests"
    assert result.status == VerificationStatus.PASS
    assert "passed" in result.message
    assert result.duration_seconds >= 0


def test_runner_fails_when_tests_fail(tmp_path):
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

    runner = TestRunner()

    result = runner.verify(project)

    assert result.name == "tests"
    assert result.status == VerificationStatus.FAIL
    assert "failed" in result.message.lower()


def test_runner_errors_for_missing_project(tmp_path):
    missing_project = tmp_path / "does-not-exist"

    runner = TestRunner()

    result = runner.verify(missing_project)

    assert result.name == "tests"
    assert result.status == VerificationStatus.ERROR