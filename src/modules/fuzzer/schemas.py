from pydantic import BaseModel, EmailStr, HttpUrl, Field
from typing import Dict, List, Optional
import enum
class HttpMethod(str, enum.Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"

class ScanRequest(BaseModel):
    openapi_url: HttpUrl = Field(..., description="The URL to OpenAPI/Swagger JSON file.")
    user_email: EmailStr = Field(..., description= "A valid email ID, where the result will be mailed.")
    target_base_url: str | None = Field(default=None, description="Override the base URL where payloads are sent (useful if openapi.json is hosted on a different domain than the live API).")
    headers: Optional[Dict[str, str]] = Field(default={}, description="Custom HTTP headers to include in every attack request (e.g., {'Authorization': 'Bearer <token>'}).")
    allowed_methods: Optional[List[HttpMethod]] = Field(
        default=[HttpMethod.GET],
        description="Limit the fuzzer to specific HTTP methods. Defaults to GET-only to prevent accidental data deletion."
    )
    requests_per_second: int | None = Field(default=5, ge=1, le=50, description="Rate limit the fuzzer to avoid triggering WAFs or 429 Too Many Requests.")