from pathlib import Path

from sentinelcode.verification.models import VerificationStatus
from sentinelcode.verification.sast import SASTVerifier


def create_project(
    tmp_path: Path,
    source: str,
) -> Path:
    project = tmp_path / "project"
    project.mkdir()

    (project / "main.py").write_text(
        source,
        encoding="utf-8",
    )

    return project


def test_sast_passes_for_safe_code(tmp_path):
    project = create_project(
        tmp_path,
        """
def add(a, b):
    return a + b
""",
    )

    verifier = SASTVerifier()

    result = verifier.verify(project)

    assert result.name == "sast"
    assert result.status == VerificationStatus.PASS
    assert result.findings == []
    assert result.duration_seconds >= 0


def test_sast_detects_shell_injection_pattern(tmp_path):
    project = create_project(
        tmp_path,
        """
import subprocess


def run_command(user_input):
    subprocess.run(user_input, shell=True)
""",
    )

    verifier = SASTVerifier()

    result = verifier.verify(project)

    assert result.name == "sast"
    assert result.status == VerificationStatus.FAIL
    assert len(result.findings) > 0
    assert result.duration_seconds >= 0

    finding = result.findings[0]

    assert finding["severity"] is not None
    assert finding["file"] is not None
    assert finding["line"] is not None


def test_sast_errors_for_missing_project(tmp_path):
    missing_project = tmp_path / "does-not-exist"

    verifier = SASTVerifier()

    result = verifier.verify(missing_project)

    assert result.name == "sast"
    assert result.status == VerificationStatus.ERROR
def test_sast_does_not_block_on_low_severity_finding(tmp_path):
    project = create_project(
        tmp_path,
        """
def check_value(value):
    assert value is not None
""",
    )

    verifier = SASTVerifier()

    result = verifier.verify(project)

    assert result.name == "sast"
    assert result.status == VerificationStatus.PASS
    assert len(result.findings) > 0

    assert all(
        finding["severity"] == "LOW"
        for finding in result.findings
    )