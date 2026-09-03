from sentinelcode.evaluation.models import (
    EvaluationRun,
    EvaluationStatus,
)
from sentinelcode.evaluation.summary import build_summary


def make_run(
    scenario_id: str,
    *,
    attack_succeeded: bool,
    task_succeeded: bool,
    detection_triggered: bool,
    blocked: bool,
    status: EvaluationStatus = EvaluationStatus.PASS,
) -> EvaluationRun:
    return EvaluationRun(
        scenario_id=scenario_id,
        protected=True,
        status=status,
        attack_succeeded=attack_succeeded,
        task_succeeded=task_succeeded,
        detection_triggered=detection_triggered,
        blocked=blocked,
    )


def test_build_summary_counts_results():
    runs = [
        make_run(
            "PI-001",
            attack_succeeded=False,
            task_succeeded=True,
            detection_triggered=True,
            blocked=True,
        ),
        make_run(
            "SF-001",
            attack_succeeded=False,
            task_succeeded=True,
            detection_triggered=True,
            blocked=True,
        ),
        make_run(
            "EX-001",
            attack_succeeded=True,
            task_succeeded=True,
            detection_triggered=True,
            blocked=False,
        ),
        make_run(
            "PK-001",
            attack_succeeded=False,
            task_succeeded=True,
            detection_triggered=True,
            blocked=True,
        ),
    ]

    summary = build_summary(runs)

    assert summary.total_runs == 4
    assert summary.attack_successes == 1
    assert summary.attacks_blocked == 3
    assert summary.detections == 4
    assert summary.task_successes == 4


def test_build_summary_calculates_rates():
    runs = [
        make_run(
            "PI-001",
            attack_succeeded=False,
            task_succeeded=True,
            detection_triggered=True,
            blocked=True,
        ),
        make_run(
            "SF-001",
            attack_succeeded=True,
            task_succeeded=True,
            detection_triggered=False,
            blocked=False,
        ),
    ]

    summary = build_summary(runs)

    assert summary.attack_success_rate == 0.5
    assert summary.attack_block_rate == 0.5
    assert summary.detection_rate == 0.5
    assert summary.task_success_rate == 1.0


def test_build_summary_preserves_runs():
    runs = [
        make_run(
            "PI-001",
            attack_succeeded=False,
            task_succeeded=True,
            detection_triggered=True,
            blocked=True,
        )
    ]

    summary = build_summary(runs)

    assert summary.runs == runs


def test_build_summary_counts_errors_separately():
    runs = [
        make_run(
            "PI-001",
            attack_succeeded=False,
            task_succeeded=False,
            detection_triggered=False,
            blocked=False,
            status=EvaluationStatus.ERROR,
        ),
        make_run(
            "SF-001",
            attack_succeeded=False,
            task_succeeded=True,
            detection_triggered=True,
            blocked=True,
        ),
    ]

    summary = build_summary(runs)

    assert summary.total_runs == 2
    assert summary.errors == 1
    assert summary.attack_successes == 0
    assert summary.attacks_blocked == 1
    assert summary.detections == 1
    assert summary.task_successes == 1