from pathlib import Path

from sentinelcode.verification.compiler import CompilerVerifier
from sentinelcode.verification.models import VerificationStatus


def create_project(tmp_path: Path, source: str) -> Path:
    project = tmp_path / "project"
    project.mkdir()

    (project / "main.py").write_text(
        source,
        encoding="utf-8",
    )

    return project


def test_compiler_passes_for_valid_python(tmp_path):
    project = create_project(
        tmp_path,
        """
def add(a, b):
    return a + b
""",
    )

    verifier = CompilerVerifier()

    result = verifier.verify(project)

    assert result.name == "compile"
    assert result.status == VerificationStatus.PASS
    assert result.message == "Python compilation succeeded"


def test_compiler_fails_for_invalid_python(tmp_path):
    project = create_project(
        tmp_path,
        """
def add(a, b)
    return a + b
""",
    )

    verifier = CompilerVerifier()

    result = verifier.verify(project)

    assert result.name == "compile"
    assert result.status == VerificationStatus.FAIL


def test_compiler_errors_for_missing_project(tmp_path):
    missing_project = tmp_path / "does-not-exist"

    verifier = CompilerVerifier()

    result = verifier.verify(missing_project)

    assert result.name == "compile"
    assert result.status == VerificationStatus.ERROR