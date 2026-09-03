from sentinelcode.evaluation.models import EvaluationStatus
from sentinelcode.evaluation.runner import SentinelBenchRunner


def test_runner_executes_all_scenarios():
    runner = SentinelBenchRunner()

    results = runner.run_all(protected=True)

    assert len(results) == 5
    assert {result.scenario_id for result in results} == {
        "PI-001",
        "SF-001",
        "EX-001",
        "PK-001",
        "VC-001",
    }


def test_protected_prompt_injection_is_blocked():
    runner = SentinelBenchRunner()

    result = runner.run_scenario("PI-001", protected=True)

    assert result.status == EvaluationStatus.PASS
    assert result.detection_triggered is True
    assert result.blocked is True
    assert result.attack_succeeded is False


def test_protected_sensitive_file_access_is_blocked():
    runner = SentinelBenchRunner()

    result = runner.run_scenario("SF-001", protected=True)

    assert result.detection_triggered is True
    assert result.blocked is True
    assert result.attack_succeeded is False


def test_protected_exfiltration_is_blocked():
    runner = SentinelBenchRunner()

    result = runner.run_scenario("EX-001", protected=True)

    assert result.detection_triggered is True
    assert result.blocked is True
    assert result.attack_succeeded is False


def test_protected_package_installation_is_blocked():
    runner = SentinelBenchRunner()

    result = runner.run_scenario("PK-001", protected=True)

    assert result.detection_triggered is True
    assert result.blocked is True
    assert result.attack_succeeded is False

def test_protected_vulnerable_code_is_blocked():
    runner = SentinelBenchRunner()

    result = runner.run_scenario("VC-001", protected=True)

    assert result.status == EvaluationStatus.PASS
    assert result.detection_triggered is True
    assert result.blocked is True
    assert result.attack_succeeded is False


def test_unprotected_vulnerable_code_succeeds():
    runner = SentinelBenchRunner()

    result = runner.run_scenario("VC-001", protected=False)

    assert result.status == EvaluationStatus.PASS
    assert result.detection_triggered is True
    assert result.blocked is False
    assert result.attack_succeeded is True

def test_unprotected_prompt_injection_succeeds():
    runner = SentinelBenchRunner()

    result = runner.run_scenario("PI-001", protected=False)

    assert result.detection_triggered is True
    assert result.blocked is False
    assert result.attack_succeeded is True


def test_runner_records_latency():
    runner = SentinelBenchRunner()

    result = runner.run_scenario("PI-001", protected=True)

    assert result.latency_ms is not None
    assert result.latency_ms >= 0


def test_unknown_scenario_returns_error():
    runner = SentinelBenchRunner()

    result = runner.run_scenario(
        "UNKNOWN",
        protected=True,
    )

    assert result.status == EvaluationStatus.ERROR
    assert result.attack_succeeded is False
    assert result.blocked is False
