import re
from datetime import datetime

from sentinelcode.models.threat_event import ThreatEvent


class PackageInstallationDetector:
    """
    Detects package installation commands issued by coding agents.
    """

    INSTALL_PATTERNS = {
        "pip": r"^\s*pip(?:3)?\s+install\s+(.+)$",
        "npm": r"^\s*npm\s+install\s+(.+)$",
        "maven": r"^\s*mvn\s+dependency:(?:get|add)\s+(.+)$",
    }
    def assess_risk(self, command: str) -> str:
        """
        Return a simple package-installation risk level.
        """

        normalized = command.lower()

        if "--extra-index-url" in normalized:
            return "HIGH"

        if "http://" in normalized or "https://" in normalized:
            return "HIGH"

        if "git+" in normalized:
            return "HIGH"

        return "MEDIUM"

    def detect(self, command: str) -> dict | None:
        """
        Detect a package installation command.
        """

        for manager, pattern in self.INSTALL_PATTERNS.items():

            match = re.match(
                pattern,
                command,
                re.IGNORECASE,
            )

            if not match:
                continue

            package_arguments = match.group(1).strip()

            packages = [
                argument
                for argument in package_arguments.split()
                if not argument.startswith("-")
            ]

            if not packages:
                return None

            return {
                "package_manager": manager,
                "package": packages[0],
                "packages": packages,
            }

        return None
    def analyze(
    self,
    command: str,
    source: str = "shell",
) -> ThreatEvent | None:
        """
        Analyze a command for package installation risk.
        """

        package_info = self.detect(command)

        if package_info is None:
            return None

        risk = self.assess_risk(command)

        if risk == "HIGH":
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        return ThreatEvent(
            threat_type="PACKAGE_INSTALLATION",
            severity=severity,
            reason=(
                f"{package_info['package_manager']} package "
                f"installation detected: "
                f"{package_info['package']} "
                f"from {source}."
            ),
            detected_at=datetime.now(),
            related_events=[],
        )