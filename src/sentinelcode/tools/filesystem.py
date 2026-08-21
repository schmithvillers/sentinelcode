from pathlib import Path


class FileSystemTool:
    """
    Provides filesystem operations.
    """

    def read(self, path: str) -> str:
        """
        Read contents of a file.
        """

        file_path = Path(path)

        return file_path.read_text()


    def write(self, path: str, content: str):
        """
        Write contents to a file.
        """

        file_path = Path(path)

        file_path.write_text(content)