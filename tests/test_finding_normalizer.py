from sentinelcode.verification.models import VerificationFinding
from sentinelcode.verification.normalizer import FindingNormalizer


def test_normalizes_bandit_finding():
    finding = {
        "test_id": "B602",
        "test_name": "subprocess_popen_with_shell_equals_true",
        "severity": "HIGH",
        "confidence": "HIGH",
        "message": "subprocess call with shell=True identified",
        "file": "main.py",
        "line": 10,
        "line_range": [10],
        "code": "subprocess.run(command, shell=True)",
    }

    result = FindingNormalizer.normalize(
        "bandit",
        finding,
    )

    assert isinstance(result, VerificationFinding)
    assert result.scanner == "bandit"
    assert result.finding_type == "SAST"
    assert result.severity == "HIGH"
    assert result.message == (
        "subprocess call with shell=True identified"
    )
    assert result.file == "main.py"
    assert result.line == 10
    assert result.identifier == "B602"


def test_normalizes_gitleaks_finding():
    finding = {
        "rule_id": "private-key",
        "description": "Private Key",
        "file": "private_key.pem",
        "line": 1,
        "secret": "[REDACTED]",
        "match": "[REDACTED]",
    }

    result = FindingNormalizer.normalize(
        "gitleaks",
        finding,
    )

    assert result.scanner == "gitleaks"
    assert result.finding_type == "SECRET"
    assert result.severity == "HIGH"
    assert result.message == "Private Key"
    assert result.file == "private_key.pem"
    assert result.line == 1
    assert result.identifier == "private-key"


def test_normalizes_dependency_finding():
    finding = {
        "package": "requests",
        "version": "2.19.0",
        "id": "PYSEC-TEST-001",
        "description": "Known vulnerability",
        "fix_versions": ["2.20.0"],
    }

    result = FindingNormalizer.normalize(
        "pip-audit",
        finding,
    )

    assert result.scanner == "pip-audit"
    assert result.finding_type == "DEPENDENCY"
    assert result.severity == "HIGH"
    assert result.message == "Known vulnerability"
    assert result.package == "requests"
    assert result.version == "2.19.0"
    assert result.identifier == "PYSEC-TEST-001"


def test_normalizes_multiple_findings():
    findings = [
        {
            "test_id": "B602",
            "severity": "HIGH",
            "message": "Shell execution",
            "file": "main.py",
            "line": 10,
        },
        {
            "test_id": "B307",
            "severity": "MEDIUM",
            "message": "Use of eval",
            "file": "utils.py",
            "line": 5,
        },
    ]

    results = FindingNormalizer.normalize_check(
        "bandit",
        findings,
    )

    assert len(results) == 2
    assert results[0].identifier == "B602"
    assert results[1].identifier == "B307"


def test_unknown_scanner_is_supported():
    finding = {
        "message": "Unknown security issue",
    }

    result = FindingNormalizer.normalize(
        "custom-scanner",
        finding,
    )

    assert result.scanner == "custom-scanner"
    assert result.finding_type == "UNKNOWN"
    assert result.severity == "UNKNOWN"
    assert result.message == "Unknown security issue"