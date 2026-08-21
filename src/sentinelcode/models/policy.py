from dataclasses import dataclass
from typing import List


@dataclass
class Policy:
    """
    Defines what an agent is allowed or denied to do.
    """

    name: str
    allowed_tools: List[str]
    blocked_resources: List[str]
    allowed_commands: List[str]
    allowed_network_hosts: List[str]