from sentinelcode.evaluation.models import (
    AttackScenario,
    EvaluationRun,
    EvaluationStatus,
    EvaluationSummary,
)


def test_attack_scenario_creation():
    scenario = AttackScenario(
        scenario_id="test-001",
        name="Test Attack",
        category="prompt_injection",
        description="A test attack scenario.",
    )

    assert scenario.scenario_id == "test-001"
    assert scenario.name == "Test Attack"
    assert scenario.category == "prompt_injection"


def test_evaluation_run_creation():
    run = EvaluationRun(
        scenario_id="test-001",
        protected=True,
        status=EvaluationStatus.PASS,
        attack_succeeded=False,
        task_succeeded=True,
        detection_triggered=True,
        blocked=True,
    )

    assert run.protected is True
    assert run.attack_succeeded is False
    assert run.task_succeeded is True
    assert run.detection_triggered is True
    assert run.blocked is True


def test_evaluation_summary_calculates_rates():
    summary = EvaluationSummary(
        total_runs=4,
        attack_successes=1,
        attacks_blocked=3,
        detections=3,
        task_successes=4,
    )

    assert summary.attack_success_rate == 0.25
    assert summary.attack_block_rate == 0.75
    assert summary.detection_rate == 0.75
    assert summary.task_success_rate == 1.0


def test_empty_summary_returns_zero_rates():
    summary = EvaluationSummary()

    assert summary.attack_success_rate == 0.0
    assert summary.attack_block_rate == 0.0
    assert summary.detection_rate == 0.0
    assert summary.task_success_rate == 0.0