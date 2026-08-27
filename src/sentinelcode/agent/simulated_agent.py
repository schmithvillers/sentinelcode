from sentinelcode.models.tool_request import ToolRequest
from sentinelcode.models.decision import Decision
from sentinelcode.runtime.runtime import SentinelRuntime


class SimulatedAgent:
    """
    A controlled coding-agent simulation.

    The agent does not directly execute tools.
    All actions are submitted to SentinelRuntime.
    """

    def __init__(
        self,
        name: str,
        runtime: SentinelRuntime
    ):
        self.name = name
        self.runtime = runtime

    def read_file(self, path: str) -> Decision:
        request = ToolRequest(
            agent=self.name,
            tool="filesystem",
            action="read",
            resource=path,
        )

        return self.runtime.evaluate_request(request)

    def write_file(self, path: str) -> Decision:
        request = ToolRequest(
            agent=self.name,
            tool="filesystem",
            action="write",
            resource=path,
        )

        return self.runtime.evaluate_request(request)

    def execute_command(self, command: str) -> Decision:
        request = ToolRequest(
            agent=self.name,
            tool="shell",
            action="execute",
            resource=command,
        )

        return self.runtime.evaluate_request(request)

    def network_request(self, host: str) -> Decision:
        request = ToolRequest(
            agent=self.name,
            tool="network",
            action="request",
            resource=host,
        )

        return self.runtime.evaluate_request(request)
    def install_package( self, package_manager: str, package: str, ) -> Decision:

        if package_manager == "pip":
            command = f"pip install {package}"

        elif package_manager == "npm":
            command = f"npm install {package}"

        elif package_manager == "maven":
            command = f"mvn dependency:get {package}"

        else:
            raise ValueError(
                f"Unsupported package manager: {package_manager}"
            )

        return self.execute_command(command)