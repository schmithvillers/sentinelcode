from sentinelcode.evaluation.report import run_evaluation


def test_run_evaluation_executes_baseline_and_protected_runs():
    report = run_evaluation()

    assert report.baseline.total_runs == 5
    assert report.protected.total_runs == 5


def test_protected_mode_blocks_more_attacks():
    report = run_evaluation()

    assert (
        report.protected.attacks_blocked
        > report.baseline.attacks_blocked
    )


def test_attack_prevention_rate_is_calculated():
    report = run_evaluation()

    assert report.attack_prevention_rate > 0.0
    assert report.attack_prevention_rate <= 1.0


def test_detection_improvement_is_calculated():
    report = run_evaluation()

    assert report.detection_improvement >= 0.0


def test_task_success_change_is_available():
    report = run_evaluation()

    assert isinstance(report.task_success_change, float)