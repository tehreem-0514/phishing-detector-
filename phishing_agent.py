from dotenv import load_dotenv
import os, json
from google import genai

load_dotenv()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

def run_phishing_agent(url: str, features: dict, prediction: str, alerts: list = None):
    alerts = alerts or []
    alerts_md = (
        "\n".join(f"- {a}" for a in alerts)
        if alerts and prediction.upper() != "PHISHING"
        else "No significant suspicious features detected."
    )

    prompt_text = (
        f"You are a cybersecurity phishing expert.\n"
        f"A URL was classified as {prediction}.\n"
        f"URL: {url}\n\n"
        f"Features:\n{json.dumps(features, indent=2)}\n\n"
        "Generate a structured report using Markdown with the following headings:\n\n"
        "Classification Summary\n"
        f"Explain clearly why the URL is considered {prediction}.\n\n"
        "Key Suspicious Features\n"
        f"{alerts_md}\n\n"
        "Recommendations\n"
        "Provide 3-5 concise, actionable steps for the user.\n\n"
        "Rules:\n"
        "- Use simple, clear sentences.\n"
        "- Keep the total report under 150 words.\n"
        "- Avoid repetition.\n"
        "- Ensure all three headings appear exactly as above."
    )

    response = client.models.generate_content(
        model="models/gemma-3-27b-it",
        contents=[{"role": "user", "parts": [{"text": prompt_text}]}],
        config=genai.types.GenerateContentConfig(
            temperature=0.2,
            max_output_tokens=400
        )
    )

    return response.text if getattr(response, "text", None) else (
        "### Classification Summary\nUnable to generate report.\n\n"
        "### Key Suspicious Features\nN/A\n\n"
        "### Recommendations\nPlease retry."
    )
