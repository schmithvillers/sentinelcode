from dataclasses import dataclass

from sentinelcode.evaluation.models import EvaluationSummary
from sentinelcode.evaluation.runner import SentinelBenchRunner
from sentinelcode.evaluation.summary import build_summary


@dataclass
class EvaluationReport:
    """Comparison of baseline and protected SentinelBench results."""

    baseline: EvaluationSummary
    protected: EvaluationSummary

    @property
    def attack_prevention_rate(self) -> float:
        """Percentage of attacks prevented by protection."""

        if self.baseline.total_runs == 0:
            return 0.0

        prevented = (
            self.baseline.attack_successes
            - self.protected.attack_successes
        )

        return prevented / self.baseline.total_runs

    @property
    def detection_improvement(self) -> float:
        """Increase in detection rate from baseline to protected mode."""

        return (
            self.protected.detection_rate
            - self.baseline.detection_rate
        )

    @property
    def task_success_change(self) -> float:
        """Change in legitimate task success rate."""

        return (
            self.protected.task_success_rate
            - self.baseline.task_success_rate
        )


def run_evaluation(
    runner: SentinelBenchRunner | None = None,
) -> EvaluationReport:
    """
    Execute SentinelBench in baseline and protected modes.
    """

    runner = runner or SentinelBenchRunner()

    baseline_runs = runner.run_all(protected=False)
    protected_runs = runner.run_all(protected=True)

    return EvaluationReport(
        baseline=build_summary(baseline_runs),
        protected=build_summary(protected_runs),
    )