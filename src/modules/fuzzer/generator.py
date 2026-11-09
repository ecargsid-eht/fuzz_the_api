import json
import asyncio
from google import genai
from google.genai import types
from src.core.config import settings

client = genai.Client(api_key=settings.GEMINI_API_KEY)


def _json_safe(obj):
    if hasattr(obj, "keys"):
        return dict(obj)
    if isinstance(obj, (list, tuple, set)):
        return list(obj)
    return str(obj)


# Structured key-value schema: eliminates double-escaped JSON strings completely
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
                        "description": "Short test category name (e.g., Boundary, Type Confusion, Auth, Input Validation)."
                    },
                    "query_params": {
                        "type": "array",
                        "description": "List of URL/query parameter key-value pairs.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "key": {"type": "string"},
                                "value": {"type": "string"}
                            },
                            "required": ["key", "value"]
                        }
                    },
                    "body_fields": {
                        "type": "array",
                        "description": "List of request body key-value pairs matching the schema properties.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "key": {"type": "string"},
                                "value": {"type": "string"}
                            },
                            "required": ["key", "value"]
                        }
                    }
                },
                "required": ["test_type", "query_params", "body_fields"]
            }
        }
    },
    "required": ["payloads"]
}


def _coerce_value(val: str):
    """Converts stringified booleans, numbers, arrays, or objects into native Python types."""
    val_stripped = val.strip()
    if val_stripped in ("true", "false", "null") or val_stripped.startswith(("{", "[")):
        try:
            return json.loads(val_stripped)
        except Exception:
            pass
    try:
        if "." in val_stripped:
            return float(val_stripped)
        return int(val_stripped)
    except ValueError:
        return val


async def generate_attack_payloads(endpoint: dict) -> list[dict]:
    system_instruction = (
        "You are an automated API validation and security testing engine. "
        "Output strictly structured JSON matching the response schema. "
        "CRITICAL: Never invent or hallucinate field names. "
        "Use ONLY the exact field names found in 'URL Parameters' and 'Request Body Schema'. "
        "Keep every test value concise (under 40 characters)."
    )

    # Extract only property names/types if full schema is passed so prompt stays compact
    raw_body_schema = endpoint.get("body_schema", {})
    if isinstance(raw_body_schema, dict) and "properties" in raw_body_schema:
        compact_body_schema = {
            k: {
                "type": v.get("type", "string") if isinstance(v, dict) else "string",
                "format": v.get("format") if isinstance(v, dict) else None,
            }
            for k, v in raw_body_schema["properties"].items()
        }
    else:
        compact_body_schema = raw_body_schema

    prompt = f"""
Generate 3 distinct API test payloads for this route:

Target Context:
- Path: {endpoint['path']}
- Method: {endpoint['method']}
- URL Parameters: {json.dumps(endpoint.get('parameters', []), default=_json_safe)}
- Request Body Schema: {json.dumps(compact_body_schema, default=_json_safe)}

Rules:
1. Map test values strictly to the exact field names listed above.
2. Keep values short and self-contained.
"""

    max_retries = 3

    for attempt in range(max_retries):
        raw_text = ""
        try:
            response = await client.aio.models.generate_content(
                model="gemini-3.5-flash-lite",
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    response_mime_type="application/json",
                    response_schema=GEMINI_SCHEMA,
                    temperature=0.2,
                    max_output_tokens=4096,
                    # CRITICAL: Disable thinking so thinking tokens don't truncate the JSON output
                    thinking_config=types.ThinkingConfig(
                        thinking_level=types.ThinkingLevel.MINIMAL
                    ),
                ),
            )

            raw_text = (response.text or "").strip()
            if raw_text.startswith("```json"):
                raw_text = raw_text[7:-3].strip()
            elif raw_text.startswith("```"):
                raw_text = raw_text[3:-3].strip()

            result = json.loads(raw_text)
            raw_payloads = result.get("payloads", [])

            # Convert structured key-value pairs into the dictionary format run_fuzzer uses
            formatted_payloads = []
            for item in raw_payloads:
                q_dict = {kv["key"]: _coerce_value(kv["value"]) for kv in item.get("query_params", [])}
                b_dict = {kv["key"]: _coerce_value(kv["value"]) for kv in item.get("body_fields", [])}

                formatted_payloads.append({
                    "test_type": item.get("test_type", "Unknown"),
                    "query_params_json": q_dict,
                    "body_json": b_dict,
                })

            return formatted_payloads

        except json.JSONDecodeError as e:
            finish_reason = (
                response.candidates[0].finish_reason
                if "response" in locals() and response.candidates
                else "UNKNOWN"
            )
            print(f"[WARN] JSON Decode Error on attempt {attempt + 1} for {endpoint['path']}: {e}")
            print(f"[DEBUG] Finish Reason: {finish_reason} | Raw Text: {repr(raw_text)}")
            if attempt == max_retries - 1:
                return []
            await asyncio.sleep(2)
        except Exception as e:
            error_str = str(e)
            if "503" in error_str or "429" in error_str:
                sleep_time = 2 ** (attempt + 1)
                print(f"[WARN] Gemini Server Overloaded. Retrying {endpoint['path']} in {sleep_time}s...")
                await asyncio.sleep(sleep_time)
            else:
                print(f"[ERROR] Fatal API Error generating payloads for {endpoint['path']}: {e}")
                return []

    return []