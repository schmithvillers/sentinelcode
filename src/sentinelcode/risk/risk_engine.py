from sentinelcode.models.tool_request import ToolRequest


class RiskEngine:
    """
    Calculates a deterministic risk score for an agent action.
    """

    def calculate_risk(self, request: ToolRequest) -> int:
        """
        Calculate the risk score for a ToolRequest.

        Returns:
            An integer between 0 and 100.
        """

        if request.tool == "filesystem":
            return self._filesystem_risk(request)

        if request.tool == "shell":
            return self._shell_risk(request)

        if request.tool == "network":
            return self._network_risk(request)

        # Unknown tools are treated as high risk.
        return 80

    def _filesystem_risk(self, request: ToolRequest) -> int:
        resource = request.resource.lower()

        if resource.endswith(".env"):
            return 70
        if "id_rsa" in resource or "id_ed25519" in resource:
            return 90

        if ".ssh" in resource:
            return 80

        if request.action == "write":
            return 15

        if request.action == "read":
            return 5

        return 20

    def _shell_risk(self, request: ToolRequest) -> int:
        command = request.resource.lower().strip()

        if command.startswith("sudo"):
            return 90

        if "rm -rf" in command:
            return 100

        if "curl" in command or "wget" in command:
            return 60

        if command.startswith("pytest"):
            return 10

        if command.startswith("git"):
            return 10

        if command.startswith("python"):
            return 15

        if command.startswith("npm"):
            return 30

        return 40

    def _network_risk(self, request: ToolRequest) -> int:
        return 35