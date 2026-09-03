from google import genai


class GeminiClient:
    """Small wrapper around the Gemini API."""

    def __init__(
        self,
        project: str,
        location: str = "global",
        model: str = "gemini-2.5-flash",
    ):
        self.project = project
        self.location = location
        self.model = model

        self.client = genai.Client(
            vertexai=True,
            project=project,
            location=location,
        )

    def analyze(self, prompt: str) -> str:
        """Send a prompt to Gemini and return the generated text."""

        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
        )

        return response.text