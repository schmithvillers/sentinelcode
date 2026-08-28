from sentinelcode.verification.models import (
    VerificationCheck,
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