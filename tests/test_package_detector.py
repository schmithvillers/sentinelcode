from sentinelcode.detection.package_detector import (
    PackageInstallationDetector,
)


def test_detects_pip_install():

    detector = PackageInstallationDetector()

    result = detector.detect(
        "pip install requests"
    )

    assert result is not None
    assert result["package_manager"] == "pip"
    assert result["package"] == "requests"


def test_detects_pip3_install():

    detector = PackageInstallationDetector()

    result = detector.detect(
        "pip3 install flask"
    )

    assert result is not None
    assert result["package_manager"] == "pip"
    assert result["package"] == "flask"


def test_detects_npm_install():

    detector = PackageInstallationDetector()

    result = detector.detect(
        "npm install express"
    )

    assert result is not None
    assert result["package_manager"] == "npm"
    assert result["package"] == "express"


def test_detects_maven_install():

    detector = PackageInstallationDetector()

    result = detector.detect(
        "mvn dependency:get commons-io:commons-io"
    )

    assert result is not None
    assert result["package_manager"] == "maven"


def test_normal_command_is_not_package_install():

    detector = PackageInstallationDetector()

    result = detector.detect(
        "pytest"
    )

    assert result is None
def test_detects_pip_install_with_flag():

    detector = PackageInstallationDetector()

    result = detector.detect(
        "pip install --upgrade requests"
    )

    assert result is not None
    assert result["package"] == "requests"


def test_detects_multiple_packages():

    detector = PackageInstallationDetector()

    result = detector.detect(
        "pip install requests flask"
    )

    assert result is not None
    assert result["packages"] == [
        "requests",
        "flask",
    ]
def test_normal_package_install_is_medium_risk():

    detector = PackageInstallationDetector()

    risk = detector.assess_risk(
        "pip install requests"
    )

    assert risk == "MEDIUM"


def test_direct_url_install_is_high_risk():

    detector = PackageInstallationDetector()

    risk = detector.assess_risk(
        "pip install https://example.com/package.tar.gz"
    )

    assert risk == "HIGH"


def test_git_install_is_high_risk():

    detector = PackageInstallationDetector()

    risk = detector.assess_risk(
        "pip install git+https://github.com/example/repo.git"
    )

    assert risk == "HIGH"
def test_analyze_returns_threat_event():

    detector = PackageInstallationDetector()

    threat = detector.analyze(
        "pip install requests"
    )

    assert threat is not None
    assert threat.threat_type == "PACKAGE_INSTALLATION"
    assert threat.severity == "MEDIUM"
    assert "requests" in threat.reason


def test_analyze_marks_direct_url_as_high():

    detector = PackageInstallationDetector()

    threat = detector.analyze(
        "pip install https://example.com/package.tar.gz"
    )

    assert threat is not None
    assert threat.severity == "HIGH"


def test_analyze_returns_none_for_normal_command():

    detector = PackageInstallationDetector()

    threat = detector.analyze(
        "pytest"
    )

    assert threat is None