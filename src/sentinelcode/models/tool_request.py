# Conceptually, every action an agent wants to perform becomes a ToolRequest

from dataclasses import dataclass

# Python's dataclass automatically gives us a convenient object for storing structured data.
@dataclass
class ToolRequest:
    """
    Represents an action requested by an autonomous coding agent.
    """

    agent: str
    tool: str
    action: str
    resource: str