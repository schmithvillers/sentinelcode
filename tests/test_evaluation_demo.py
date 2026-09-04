from sentinelcode.evaluation.demo import main


def test_demo_completes_successfully(capsys):
    exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "SentinelCode Demo" in captured.out
    assert "Protected scenarios: 5/5 blocked" in captured.out
    assert "All controlled scenarios were blocked." in captured.out


def test_demo_reports_all_scenarios(capsys):
    main()

    output = capsys.readouterr().out

    for scenario_id in (
        "PI-001",
        "SF-001",
        "EX-001",
        "PK-001",
        "VC-001",
    ):
        assert scenario_id in output

    assert output.count("BLOCKED") == 5