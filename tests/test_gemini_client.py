from unittest.mock import MagicMock, patch

from sentinelcode.intelligence.gemini_client import GeminiClient


@patch("sentinelcode.intelligence.gemini_client.genai.Client")
def test_gemini_client_initializes(mock_client):
    client = GeminiClient(project="sentinelcode")

    mock_client.assert_called_once_with(
        vertexai=True,
        project="sentinelcode",
        location="global",
    )

    assert client.project == "sentinelcode"
    assert client.location == "global"
    assert client.model == "gemini-2.5-flash"


@patch("sentinelcode.intelligence.gemini_client.genai.Client")
def test_gemini_client_analyze(mock_client):
    mock_response = MagicMock()
    mock_response.text = "This event appears suspicious."

    mock_client.return_value.models.generate_content.return_value = (
        mock_response
    )

    client = GeminiClient(project="sentinelcode")

    result = client.analyze("Analyze this security event.")

    assert result == "This event appears suspicious."

    mock_client.return_value.models.generate_content.assert_called_once_with(
        model="gemini-2.5-flash",
        contents="Analyze this security event.",
    )