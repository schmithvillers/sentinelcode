import json
import subprocess
import time
from pathlib import Path
from typing import Any

from sentinelcode.verification.models import (
    VerificationCheck,
    VerificationStatus,
)


class SecretScanner:
    """Scans a project for exposed secrets using Gitleaks."""

    def verify(self, project_path: str | Path) -> VerificationCheck:
        project = Path(project_path)

        if not project.exists():
            return VerificationCheck(
                name="secrets",
                status=VerificationStatus.ERROR,
                message=f"Project path does not exist: {project}",
            )

        start = time.perf_counter()

        try:
            result = subprocess.run(
                [
                    "gitleaks",
                    "dir",
                    str(project),
                    "--report-format",
                    "json",
                    "--report-path",
                    str(project / ".gitleaks-report.json"),
                    "--no-banner",
                ],
                capture_output=True,
                text=True,
                cwd=project,
            )

            duration = time.perf_counter() - start

            findings = self._read_findings(
                project / ".gitleaks-report.json"
            )

            self._remove_report(
                project / ".gitleaks-report.json"
            )

            if result.returncode == 0:
                return VerificationCheck(
                    name="secrets",
                    status=VerificationStatus.PASS,
                    message="No secrets detected",
                    findings=findings,
                    duration_seconds=duration,
                )

            if result.returncode == 1:
                return VerificationCheck(
                    name="secrets",
                    status=VerificationStatus.FAIL,
                    message=f"Gitleaks detected {len(findings)} potential secret(s)",
                    findings=findings,
                    duration_seconds=duration,
                )

            return VerificationCheck(
                name="secrets",
                status=VerificationStatus.ERROR,
                message=(
                    result.stderr.strip()
                    or "Gitleaks execution failed"
                ),
                findings=findings,
                duration_seconds=duration,
            )

        except FileNotFoundError:
            duration = time.perf_counter() - start

            return VerificationCheck(
                name="secrets",
                status=VerificationStatus.ERROR,
                message=(
                    "Gitleaks is not installed or is not available "
                    "on PATH"
                ),
                duration_seconds=duration,
            )

        except OSError as exc:
            duration = time.perf_counter() - start

            return VerificationCheck(
                name="secrets",
                status=VerificationStatus.ERROR,
                message=f"Unable to run Gitleaks: {exc}",
                duration_seconds=duration,
            )

    @staticmethod
    def _read_findings(
        report_path: Path,
    ) -> list[dict[str, Any]]:
        if not report_path.exists():
            return []

        try:
            content = report_path.read_text(
                encoding="utf-8"
            )

            if not content.strip():
                return []

            data = json.loads(content)

            if not isinstance(data, list):
                return []

            findings = []

            for finding in data:
                findings.append(
                    {
                        "rule_id": finding.get("RuleID"),
                        "description": finding.get("Description"),
                        "file": finding.get("File"),
                        "line": finding.get("StartLine"),
                        "end_line": finding.get("EndLine"),
                        "secret": "[REDACTED]",
                        "match": "[REDACTED]",
                        "commit": finding.get("Commit"),
                    }
                )

            return findings

        except (OSError, json.JSONDecodeError):
            return []

    @staticmethod
    def _remove_report(report_path: Path) -> None:
        try:
            report_path.unlink(missing_ok=True)
        except OSError:
            pass