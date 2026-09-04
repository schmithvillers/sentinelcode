from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_PATH = PROJECT_ROOT / "dashboard" / "index.html"
RESULTS_PATH = PROJECT_ROOT / "evaluation_results" / "sentinelbench_results.json"


def test_dashboard_exists():
    assert DASHBOARD_PATH.exists()
    assert DASHBOARD_PATH.is_file()


def test_dashboard_contains_expected_sections():
    content = DASHBOARD_PATH.read_text(encoding="utf-8")

    assert "SentinelBench Security Evaluation Dashboard" in content
    assert "Baseline vs. Protected" in content
    assert "Scenario Results" in content
    assert "Benchmark Scope" in content


def test_dashboard_loads_benchmark_results():
    content = DASHBOARD_PATH.read_text(encoding="utf-8")

    assert "../evaluation_results/sentinelbench_results.json" in content


def test_benchmark_results_exist():
    assert RESULTS_PATH.exists()
    assert RESULTS_PATH.is_file()