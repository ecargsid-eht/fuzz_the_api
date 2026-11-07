from pydantic import BaseModel, EmailStr, HttpUrl, Field, field_validator
from typing import Dict, List, Optional
import enum
from .models import JobStatus
import socket
import ipaddress
from urllib.parse import urlparse
from datetime import datetime

class HttpMethod(str, enum.Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"

class ScanRequest(BaseModel):
    openapi_url: HttpUrl = Field(..., description="The URL to OpenAPI/Swagger JSON file.")
    target_base_url: str | None = Field(default=None, description="Override the base URL where payloads are sent (useful if openapi.json is hosted on a different domain than the live API).")
    headers: Optional[Dict[str, str]] = Field(default={}, description="Custom HTTP headers to include in every attack request (e.g., {'Authorization': 'Bearer <token>'}).")
    allowed_methods: Optional[List[HttpMethod]] = Field(
        default=[HttpMethod.GET],
        description="Limit the fuzzer to specific HTTP methods. Defaults to GET-only to prevent accidental data deletion."
    )
    requests_per_second: int | None = Field(default=5, ge=1, le=50, description="Rate limit the fuzzer to avoid triggering WAFs or 429 Too Many Requests.")

    @field_validator("openapi_url", "target_base_url")
    @classmethod
    def validate_public_urls(cls, v):
        if not v: # Skip if target_base_url is None
            return v
            
        hostname = urlparse(str(v)).hostname
        if not hostname:
            return v

        # 1. Block literal strings
        if hostname in ["localhost", "127.0.0.1", "0.0.0.0"]:
            raise ValueError(f"Localhost is blocked for {v}. Please use a port forwarder like Ngrok.")
            
        # 2. Block DNS rebinding to private IPs
        try:
            ip = socket.gethostbyname(hostname)
            if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback:
                raise ValueError(f"URL {v} resolves to a private IP. Please use a port forwarder like Ngrok.")
        except socket.gaierror:
            raise ValueError(f"Hostname for {v} could not be resolved.")
            
        return v

class ScanResponse(BaseModel):
    id: int
    target_base_url: str
    openapi_url: str
    status: JobStatus
    vulnerabilities_found: int
    created_at: datetime

    class Config:
        from_attributes = True