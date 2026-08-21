from sentinelcode.models.tool_request import ToolRequest
from sentinelcode.models.policy import Policy


class PolicyEngine:
    """
    Evaluates ToolRequests against security policies.
    """

    def __init__(self, policy: Policy):
        self.policy = policy


    def evaluate(self, request: ToolRequest) -> bool:
        """
        Returns:
            True  -> action allowed
            False -> action blocked
        """

        # Check tool permission
        if request.tool not in self.policy.allowed_tools:
            return False


        # Check blocked resources
        for blocked_resource in self.policy.blocked_resources:
            if blocked_resource in request.resource:
                return False


        # Check shell commands
        if request.tool == "shell":
            return self._check_command(request.resource)


        # Check network destinations
        if request.tool == "network":
            return self._check_network(request.resource)


        return True


    def _check_command(self, command: str) -> bool:
        """
        Check whether a shell command is allowed.
        """

        command = command.lower()

        for allowed_command in self.policy.allowed_commands:
            if command.startswith(allowed_command):
                return True

        return False


    def _check_network(self, host: str) -> bool:
        """
        Check whether network destination is trusted.
        """

        return host in self.policy.allowed_network_hosts