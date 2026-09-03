import json

from sentinelcode.evaluation.report import run_evaluation
from sentinelcode.evaluation.results import save_report


def test_save_report_writes_json(tmp_path):
    report = run_evaluation()

    output_path = tmp_path / "evaluation.json"

    saved_path = save_report(
        report,
        output_path,
    )

    assert saved_path == output_path
    assert output_path.exists()

    data = json.loads(
        output_path.read_text(encoding="utf-8")
    )

    assert "baseline" in data
    assert "protected" in data
    assert "comparison" in data


def test_save_report_contains_comparison_metrics(tmp_path):
    report = run_evaluation()

    output_path = tmp_path / "evaluation.json"

    save_report(report, output_path)

    data = json.loads(
        output_path.read_text(encoding="utf-8")
    )

    comparison = data["comparison"]

    assert comparison["attack_prevention_rate"] == 1.0
    assert comparison["detection_improvement"] == 0.0
    assert comparison["task_success_change"] == 0.0