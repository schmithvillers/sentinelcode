from sentinelcode.models.decision import Decision


def test_decision_creation():
    decision = Decision(
        decision="BLOCK",
        risk_score=70,
        reason="Sensitive credential file"
    )

    assert decision.decision == "BLOCK"
    assert decision.risk_score == 70
    assert decision.reason == "Sensitive credential file"