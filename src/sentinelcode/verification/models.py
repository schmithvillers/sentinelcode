from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class VerificationStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


@dataclass
class VerificationFinding:
    """Normalized security or verification finding."""

    scanner: str
    finding_type: str
    severity: str
    message: str
    file: str | None = None
    line: int | None = None
    package: str | None = None
    version: str | None = None
    identifier: str | None = None


@dataclass
class VerificationCheck:
    name: str
    status: VerificationStatus
    message: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    duration_seconds: float = 0.0


@dataclass
class VerificationResult:
    status: VerificationStatus
    checks: list[VerificationCheck] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.status == VerificationStatus.PASS

    @property
    def failed(self) -> bool:
        return self.status == VerificationStatus.FAIL