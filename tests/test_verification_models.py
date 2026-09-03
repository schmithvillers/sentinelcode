from sentinelcode.verification.models import (
    VerificationCheck,
    VerificationFinding,
    VerificationResult,
    VerificationStatus,
)


def test_successful_verification_check():
    check = VerificationCheck(
        name="compile",
        status=VerificationStatus.PASS,
        message="Compilation succeeded",
    )

    assert check.name == "compile"
    assert check.status == VerificationStatus.PASS
    assert check.message == "Compilation succeeded"


def test_failed_verification_check():
    check = VerificationCheck(
        name="compile",
        status=VerificationStatus.FAIL,
        message="Compilation failed",
    )

    assert check.status == VerificationStatus.FAIL


def test_successful_verification_result():
    result = VerificationResult(
        status=VerificationStatus.PASS,
        checks=[
            VerificationCheck(
                name="compile",
                status=VerificationStatus.PASS,
            )
        ],
    )

    assert result.passed is True
    assert result.failed is False


def test_failed_verification_result():
    result = VerificationResult(
        status=VerificationStatus.FAIL,
        checks=[
            VerificationCheck(
                name="sast",
                status=VerificationStatus.FAIL,
            )
        ],
    )

    assert result.passed is False
    assert result.failed is True


def test_verification_finding():
    finding = VerificationFinding(
        scanner="bandit",
        finding_type="SAST",
        severity="HIGH",
        message="Use of subprocess with shell=True",
        file="main.py",
        line=10,
        identifier="B602",
    )

    assert finding.scanner == "bandit"
    assert finding.finding_type == "SAST"
    assert finding.severity == "HIGH"
    assert finding.file == "main.py"
    assert finding.line == 10
    assert finding.identifier == "B602"


def test_verification_finding_supports_dependency():
    finding = VerificationFinding(
        scanner="pip-audit",
        finding_type="DEPENDENCY",
        severity="HIGH",
        message="Known vulnerability",
        package="requests",
        version="2.19.0",
        identifier="PYSEC-TEST-001",
    )

    assert finding.package == "requests"
    assert finding.version == "2.19.0"
    assert finding.identifier == "PYSEC-TEST-001"