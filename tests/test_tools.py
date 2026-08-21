from sentinelcode.tools.filesystem import FileSystemTool
from sentinelcode.tools.shell import ShellTool
from sentinelcode.tools.network import NetworkTool



def test_filesystem_read(tmp_path):

    file = tmp_path / "test.txt"

    file.write_text("hello sentinelcode")

    tool = FileSystemTool()

    result = tool.read(str(file))

    assert result == "hello sentinelcode"



def test_filesystem_write(tmp_path):

    file = tmp_path / "output.txt"

    tool = FileSystemTool()

    tool.write(
        str(file),
        "sentinelcode"
    )

    assert file.read_text() == "sentinelcode"



def test_shell_execute():

    tool = ShellTool()

    result = tool.execute("echo hello")

    assert "hello" in result



def test_network_request():

    tool = NetworkTool()

    result = tool.request("github.com")

    assert result == "Request sent to github.com"