import json
from google import genai
from google.genai import types
from src.core.config import settings

client = genai.Client(api_key=settings.GEMINI_API_KEY)

GEMINI_SCHEMA = {
    "type": "object",
    "properties": {
        "payloads": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "test_type": {
                        "type": "string",
                        "description": "Short attack category name (e.g., SQLi, BOLA, XSS)."
                    },
                    "query_params_json": {
                        "type": "string",
                        "description": "Valid compact JSON string for query parameters. Use '{}' if empty."
                    },
                    "body_json": {
                        "type": "string",
                        "description": "Valid compact JSON string for request body. Use '{}' if empty."
                    }
                },
                "required": ["test_type", "query_params_json", "body_json"]
            }
        }
    },
    "required": ["payloads"]
}

async def generate_attack_payloads(endpoint: dict) -> list[dict]:
    """
    Generates concise, structured attack payloads without conversational drift.
    """
    system_instruction = (
        "You are an automated API fuzzing engine. Output strictly structured data. "
        "Do NOT include explanations, comments, or justifications anywhere in the values. "
        "Keep all test strings concise (under 150 characters). Do NOT generate massive repetitive character strings."
    )

    prompt = f"""
Generate 3 distinct security test payloads for this API route targeting OWASP Top 10 API vulnerabilities:

Endpoint:
- Path: {endpoint['path']}
- Method: {endpoint['method']}
- Parameters: {endpoint['parameters']}
- Accepts Body: {endpoint['has_body']}

Rules:
1. Values must contain ONLY the raw test data (no markdown, no explanations).
2. 'query_params_json' and 'body_json' must be valid, parseable JSON strings.
"""

    try:
        response = await client.aio.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                response_mime_type="application/json",
                response_schema=GEMINI_SCHEMA,
                temperature=0.2,  # Low temperature prevents hallucination & token looping
                max_output_tokens=1000,
            ),
        )

        result = json.loads(response.text)
        return result.get("payloads", [])

    except Exception as e:
        print(f"Failed to generate payloads for {endpoint['path']}: {e}")
        return []