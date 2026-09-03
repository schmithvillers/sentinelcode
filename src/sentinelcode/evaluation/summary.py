from sentinelcode.evaluation.models import (
    EvaluationRun,
    EvaluationStatus,
    EvaluationSummary,
)


def build_summary(
    runs: list[EvaluationRun],
) -> EvaluationSummary:
    """
    Build aggregate evaluation metrics from individual benchmark runs.
    """

    summary = EvaluationSummary(
        total_runs=len(runs),
        runs=list(runs),
    )

    for run in runs:
        if run.status == EvaluationStatus.ERROR:
            summary.errors += 1
            continue

        if run.attack_succeeded:
            summary.attack_successes += 1

        if run.blocked:
            summary.attacks_blocked += 1

        if run.detection_triggered:
            summary.detections += 1

        if run.task_succeeded:
            summary.task_successes += 1

    return summary