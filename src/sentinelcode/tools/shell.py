import subprocess


class ShellTool:
    """
    Provides shell command execution.
    """

    def execute(self, command: str) -> str:
        """
        Execute a shell command.
        """

        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )

        return result.stdout