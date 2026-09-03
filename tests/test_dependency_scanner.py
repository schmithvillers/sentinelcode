from pathlib import Path
from unittest.mock import patch

from sentinelcode.verification.dependencies import DependencyScanner
from sentinelcode.verification.models import VerificationStatus


def test_missing_project_returns_error(tmp_path):
    scanner = DependencyScanner()

    project = tmp_path / "does-not-exist"

    result = scanner.verify(project)

    assert result.status == VerificationStatus.ERROR
    assert result.name == "dependencies"
def test_missing_requirements_returns_skipped(tmp_path):
    scanner = DependencyScanner()

    project = tmp_path / "project"
    project.mkdir()

    result = scanner.verify(project)

    assert result.status == VerificationStatus.SKIPPED
    assert result.name == "dependencies"
@patch("sentinelcode.verification.dependencies.subprocess.run")
def test_clean_dependencies_pass(mock_run, tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    (project / "requirements.txt").write_text(
        "pytest\n",
        encoding="utf-8",
    )

    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = "[]"
    mock_run.return_value.stderr = ""

    scanner = DependencyScanner()

    result = scanner.verify(project)

    assert result.status == VerificationStatus.PASS
    assert result.name == "dependencies"
    assert result.findings == []
@patch("sentinelcode.verification.dependencies.subprocess.run")
def test_vulnerable_dependency_fails(mock_run, tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    (project / "requirements.txt").write_text(
        "requests==2.19.0\n",
        encoding="utf-8",
    )

    mock_run.return_value.returncode = 1
    mock_run.return_value.stdout = """
    [
        {
            "name": "requests",
            "version": "2.19.0",
            "id": "PYSEC-TEST-001",
            "description": "Test vulnerability",
            "fix_versions": ["2.20.0"]
        }
    ]
    """
    mock_run.return_value.stderr = ""

    scanner = DependencyScanner()

    result = scanner.verify(project)

    assert result.status == VerificationStatus.FAIL
    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding["package"] == "requests"
    assert finding["version"] == "2.19.0"
    assert finding["id"] == "PYSEC-TEST-001"
@patch("sentinelcode.verification.dependencies.subprocess.run")
def test_dependency_scanner_error(mock_run, tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    (project / "requirements.txt").write_text(
        "pytest\n",
        encoding="utf-8",
    )

    mock_run.return_value.returncode = 2
    mock_run.return_value.stdout = ""
    mock_run.return_value.stderr = "Scanner failed"

    scanner = DependencyScanner()

    result = scanner.verify(project)

    assert result.status == VerificationStatus.ERROR
    assert result.name == "dependencies"
    assert "Scanner failed" in result.message