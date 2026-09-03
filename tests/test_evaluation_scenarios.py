from sentinelcode.evaluation.scenarios import (
    ATTACK_SCENARIOS,
    get_attack_scenarios,
)


def test_sentinelbench_contains_five_scenarios():
    scenarios = get_attack_scenarios()

    assert len(scenarios) == 5


def test_scenario_ids_are_unique():
    scenarios = get_attack_scenarios()

    ids = [scenario.scenario_id for scenario in scenarios]

    assert len(ids) == len(set(ids))


def test_expected_scenario_categories_exist():
    scenarios = get_attack_scenarios()

    categories = {scenario.category for scenario in scenarios}

    assert categories == {
        "prompt_injection",
        "credential_access",
        "exfiltration",
        "supply_chain",
        "code_security",
    }


def test_all_scenarios_have_required_information():
    scenarios = get_attack_scenarios()

    for scenario in scenarios:
        assert scenario.scenario_id
        assert scenario.name
        assert scenario.category
        assert scenario.description


def test_scenarios_are_returned_as_a_copy():
    scenarios = get_attack_scenarios()

    scenarios.clear()

    assert len(ATTACK_SCENARIOS) == 5