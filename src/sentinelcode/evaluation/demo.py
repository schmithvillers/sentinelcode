from sentinelcode.evaluation.runner import SentinelBenchRunner
from sentinelcode.evaluation.scenarios import get_attack_scenarios


def main() -> int:
    print("SentinelCode Demo")
    print("=================")
    print()

    runner = SentinelBenchRunner()
    scenarios = get_attack_scenarios()

    results = []

    for scenario in scenarios:
        result = runner.run_scenario(
            scenario.scenario_id,
            protected=True,
        )
        results.append(result)

        if result.status.value == "error":
            outcome = "ERROR"
        elif result.blocked:
            outcome = "BLOCKED"
        else:
            outcome = "NOT BLOCKED"

        print(
            f"{scenario.scenario_id:<7} "
            f"{scenario.name:<35} "
            f"{outcome}"
        )

    blocked = sum(result.blocked for result in results)
    total = len(results)

    print()
    print(f"Protected scenarios: {blocked}/{total} blocked")

    errors = sum(
        result.status.value == "error"
        for result in results
    )

    if errors:
        print(f"Errors: {errors}")
        return 1

    if blocked != total:
        print("One or more controlled scenarios were not blocked.")
        return 1

    print("All controlled scenarios were blocked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())