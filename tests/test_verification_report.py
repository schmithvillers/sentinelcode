from sentinelcode.verification.models import (
    VerificationCheck,
    VerificationResult,
    VerificationStatus,
)
from sentinelcode.verification.pipeline import VerificationPipeline
from sentinelcode.verification.report import (
    VerificationReport,
    VerificationReportBuilder,
)


def test_builds_report_from_successful_result():
    result = VerificationResult(
        status=VerificationStatus.PASS,
        checks=[
            VerificationCheck(
                name="compile",
                status=VerificationStatus.PASS,
            ),
            VerificationCheck(
                name="tests",
                status=VerificationStatus.PASS,
            ),
            VerificationCheck(
                name="sast",
                status=VerificationStatus.PASS,
            ),
        ],
    )

    report = VerificationReportBuilder.build(result)

    assert isinstance(report, VerificationReport)
    assert report.status == VerificationStatus.PASS
    assert report.passed is True
    assert report.failed is False
    assert report.total_findings == 0


def test_builds_report_with_sast_finding():
    result = VerificationResult(
        status=VerificationStatus.FAIL,
        checks=[
            VerificationCheck(
                name="compile",
                status=VerificationStatus.PASS,
            ),
            VerificationCheck(
                name="sast",
                status=VerificationStatus.FAIL,
                findings=[
                    {
                        "test_id": "B602",
                        "test_name": (
                            "subprocess_popen_with_shell_equals_true"
                        ),
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "message": (
                            "subprocess call with shell=True identified"
                        ),
                        "file": "main.py",
                        "line": 10,
                    }
                ],
            ),
        ],
    )

    report = VerificationReportBuilder.build(result)

    assert report.status == VerificationStatus.FAIL
    assert report.failed is True
    assert report.total_findings == 1

    finding = report.findings[0]

    assert finding.scanner == "sast"
    assert finding.finding_type == "SAST"
    assert finding.severity == "HIGH"
    assert finding.file == "main.py"
    assert finding.line == 10
    assert finding.identifier == "B602"


def test_report_contains_dependency_finding():
    result = VerificationResult(
        status=VerificationStatus.FAIL,
        checks=[
            VerificationCheck(
                name="dependencies",
                status=VerificationStatus.FAIL,
                findings=[
                    {
                        "package": "requests",
                        "version": "2.19.0",
                        "id": "PYSEC-TEST-001",
                        "description": "Known vulnerability",
                    }
                ],
            ),
        ],
    )

    report = VerificationReportBuilder.build(result)

    assert report.total_findings == 1

    finding = report.findings[0]

    assert finding.finding_type == "DEPENDENCY"
    assert finding.package == "requests"
    assert finding.version == "2.19.0"
    assert finding.identifier == "PYSEC-TEST-001"


def test_report_renders_as_text():
    result = VerificationResult(
        status=VerificationStatus.FAIL,
        checks=[
            VerificationCheck(
                name="compile",
                status=VerificationStatus.PASS,
            ),
            VerificationCheck(
                name="sast",
                status=VerificationStatus.FAIL,
                findings=[
                    {
                        "test_id": "B602",
                        "severity": "HIGH",
                        "message": "Unsafe shell execution",
                        "file": "main.py",
                        "line": 10,
                    }
                ],
            ),
        ],
    )

    report = VerificationReportBuilder.build(result)

    text = report.to_text()

    assert "SENTINELCODE VERIFICATION REPORT" in text
    assert "Status: FAIL" in text
    assert "compile" in text
    assert "sast" in text
    assert "HIGH" in text
    assert "Unsafe shell execution" in text
    assert "main.py:10" in text
    assert "B602" in text


def test_report_renders_dependency_details():
    result = VerificationResult(
        status=VerificationStatus.FAIL,
        checks=[
            VerificationCheck(
                name="dependencies",
                status=VerificationStatus.FAIL,
                findings=[
                    {
                        "package": "requests",
                        "version": "2.19.0",
                        "id": "PYSEC-TEST-001",
                        "description": "Known vulnerability",
                    }
                ],
            ),
        ],
    )

    report = VerificationReportBuilder.build(result)

    text = report.to_text()

    assert "requests==2.19.0" in text
    assert "PYSEC-TEST-001" in text
    assert "Known vulnerability" in text