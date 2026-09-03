from dataclasses import dataclass, field
from enum import Enum


class EvaluationStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


@dataclass
class AttackScenario:
    scenario_id: str
    name: str
    category: str
    description: str


@dataclass
class EvaluationRun:
    scenario_id: str
    protected: bool
    status: EvaluationStatus
    attack_succeeded: bool
    task_succeeded: bool
    detection_triggered: bool
    blocked: bool
    latency_ms: float | None = None
    details: str = ""


@dataclass
class EvaluationSummary:
    total_runs: int = 0
    attack_successes: int = 0
    attacks_blocked: int = 0
    detections: int = 0
    task_successes: int = 0
    errors: int = 0
    runs: list[EvaluationRun] = field(default_factory=list)

    @property
    def attack_success_rate(self) -> float:
        if self.total_runs == 0:
            return 0.0

        return self.attack_successes / self.total_runs

    @property
    def attack_block_rate(self) -> float:
        if self.total_runs == 0:
            return 0.0

        return self.attacks_blocked / self.total_runs

    @property
    def detection_rate(self) -> float:
        if self.total_runs == 0:
            return 0.0

        return self.detections / self.total_runs

    @property
    def task_success_rate(self) -> float:
        if self.total_runs == 0:
            return 0.0

        return self.task_successes / self.total_runs