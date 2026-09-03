import json
from dataclasses import asdict
from pathlib import Path

from sentinelcode.evaluation.report import EvaluationReport


def save_report(
    report: EvaluationReport,
    output_path: str | Path,
) -> Path:
    """Save an evaluation report as JSON."""
    path = Path(output_path)

    data = {
        "baseline": asdict(report.baseline),
        "protected": asdict(report.protected),
        "comparison": {
            "attack_prevention_rate": report.attack_prevention_rate,
            "detection_improvement": report.detection_improvement,
            "task_success_change": report.task_success_change,
        },
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )

    return path