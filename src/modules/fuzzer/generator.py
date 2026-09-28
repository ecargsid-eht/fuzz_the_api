import json
import asyncio
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
    Generates structured attack payloads with a 3-attempt retry loop to handle 
    Google 503 overloads and malformed JSON truncations.
    """
    system_instruction = (
        "You are an automated API fuzzing engine. Output strictly structured data. "
        "Do NOT include explanations, comments, or justifications. "
        "Keep all test strings extremely concise (under 50 characters). Do NOT generate massive repetitive strings."
    )

    prompt = f"""
Generate 3 distinct security test payloads for this API route targeting OWASP Top 10 API vulnerabilities:

Endpoint:
- Path: {endpoint['path']}
- Method: {endpoint['method']}
- Parameters: {endpoint['parameters']}
- Accepts Body: {endpoint['has_body']}

Rules:
1. Values must contain ONLY the raw test data.
2. 'query_params_json' and 'body_json' must be valid, parseable JSON strings.
"""

    max_retries = 3
    
    for attempt in range(max_retries):
        try:
            response = await client.aio.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    response_mime_type="application/json",
                    response_schema=GEMINI_SCHEMA,
                    temperature=0.2,
                    max_output_tokens=2048, 
                ),
            )
            
            raw_text = response.text.strip()
            if raw_text.startswith("```json"):
                raw_text = raw_text[7:-3].strip()
            elif raw_text.startswith("```"):
                raw_text = raw_text[3:-3].strip()

            result = json.loads(raw_text)
            return result.get("payloads", [])

        except json.JSONDecodeError as e:
            print(f"⚠️ JSON Decode Error on attempt {attempt + 1} for {endpoint['path']}: {e}")
            if attempt == max_retries - 1:
                return []
            await asyncio.sleep(2)
        except Exception as e:
            error_str = str(e)
            if "503" in error_str or "429" in error_str:
                sleep_time = 2 ** (attempt + 1)
                print(f"⚠️ Gemini Server Overloaded (503). Retrying {endpoint['path']} in {sleep_time}s...")
                await asyncio.sleep(sleep_time)
            else:
                print(f"❌ Fatal API Error generating payloads for {endpoint['path']}: {e}")
                return []

    return []