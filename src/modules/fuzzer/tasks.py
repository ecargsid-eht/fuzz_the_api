import asyncio
import json
import re
import httpx
from sqlalchemy import select

from src.core.database import AsyncSessionLocal
from .generator import generate_attack_payloads
from .models import FuzzJob, FuzzResult, JobStatus
from .parser import extract_endpoints, resolve_base_url


def inject_path_params(path: str, params: dict) -> tuple[str, dict]:
    """
    Replaces {param} in path with matching keys from params,
    or falls back to a default mock value.
    """
    remaining_params = dict(params)
    for key, value in list(remaining_params.items()):
        placeholder = f"{{{key}}}"
        if placeholder in path:
            path = path.replace(placeholder, str(value))
            remaining_params.pop(key)

    # Replace any leftover un-substituted placeholders like {id} or {slug}
    path = re.sub(r"\{.*?\}", "test-val-1", path)
    return path, remaining_params


async def run_fuzzer(ctx: dict, job_id: int):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(FuzzJob).where(FuzzJob.id == job_id))
        job = result.scalar_one_or_none()

        if not job:
            return False

        job.status = JobStatus.IN_PROGRESS
        await db.commit()

        try:
            # 1. Fetch OpenAPI Specification
            async with httpx.AsyncClient(headers=job.headers) as client:
                response = await client.get(job.openapi_url, timeout=30.0, follow_redirects=True)
                spec = response.json()

            base_url = resolve_base_url(spec, job.openapi_url, job.target_base_url)
            endpoints = extract_endpoints(spec, job.allowed_methods)
            throttle_delay = 1.0 / max(job.requests_per_second, 1)

            # 2. Execute Fuzzing Loop
            async with httpx.AsyncClient(base_url=base_url, headers=job.headers) as target_client:
                for endpoint in endpoints:
                    await asyncio.sleep(throttle_delay)
                    payloads = await generate_attack_payloads(endpoint)

                    for payload in payloads:
                        await asyncio.sleep(throttle_delay)

                        # Safely deserialize JSON string payloads
                        try:
                            raw_query = payload.get("query_params_json", "{}")
                            query_params = json.loads(raw_query) if isinstance(raw_query, str) else raw_query
                        except Exception:
                            query_params = {}

                        try:
                            raw_body = payload.get("body_json", "{}")
                            body_params = json.loads(raw_body) if isinstance(raw_body, str) else raw_body
                        except Exception:
                            body_params = {}

                        # Resolve path variables (e.g., /problems/{slug})
                        resolved_path, filtered_query = inject_path_params(endpoint["path"], query_params)

                        try:
                            attack_response = await target_client.request(
                                method=endpoint["method"],
                                url=resolved_path,
                                params=filtered_query,
                                json=body_params if endpoint["has_body"] else None,
                                timeout=10.0
                            )

                            status = attack_response.status_code

                            # Log internal server errors / unhandled crashes
                            if status >= 500:
                                vuln_log = FuzzResult(
                                    job_id=job.id,
                                    endpoint_path=endpoint["path"],
                                    http_method=endpoint["method"],
                                    test_type=payload.get("test_type", "Unknown"),
                                    payload_sent={
                                        "query": query_params,
                                        "body": body_params,
                                        "resolved_url": resolved_path
                                    },
                                    status_code=status,
                                    response_body=attack_response.text[:1000],
                                    is_vulnerable=True
                                )
                                db.add(vuln_log)
                                await db.commit()

                        except httpx.RequestError as e:
                            print(f"Network error hitting target ({resolved_path}): {e}")

            job.status = JobStatus.COMPLETED
            await db.commit()
            return True

        except Exception as e:
            print(f"Job #{job_id} failed with error: {e}")
            job.status = JobStatus.FAILED
            await db.commit()
            return False