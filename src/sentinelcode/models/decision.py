from dataclasses import dataclass


@dataclass
class Decision:
    """
    Represents SentinelCode's decision about an agent action.
    """

    decision: str
    risk_score: int
    reason: str