from pathlib import Path

from sentinelcode.verification.models import VerificationStatus
from sentinelcode.verification.secrets import SecretScanner


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


def test_secret_scanner_passes_for_safe_code(tmp_path):
    project = create_project(
        tmp_path,
        """
def add(a, b):
    return a + b
""",
    )

    scanner = SecretScanner()

    result = scanner.verify(project)

    assert result.name == "secrets"
    assert result.status == VerificationStatus.PASS
    assert result.findings == []
    assert result.duration_seconds >= 0


def test_secret_scanner_detects_fake_private_key(tmp_path):
    project = create_project(
        tmp_path,
        """-----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB
        AAAAC3NzaC1yc2EAAAADAQABAAABAQCfakeSentinelCodeTestKey
        -----END OPENSSH PRIVATE KEY-----
        """,
            )

    scanner = SecretScanner()

    result = scanner.verify(project)

    assert result.name == "secrets"
    assert result.status == VerificationStatus.FAIL
    assert len(result.findings) > 0
    assert result.duration_seconds >= 0

    finding = result.findings[0]

    assert finding["rule_id"] is not None
    assert finding["file"] is not None
    assert finding["line"] is not None


def test_secret_scanner_errors_for_missing_project(tmp_path):
    missing_project = tmp_path / "does-not-exist"

    scanner = SecretScanner()

    result = scanner.verify(missing_project)

    assert result.name == "secrets"
    assert result.status == VerificationStatus.ERROR