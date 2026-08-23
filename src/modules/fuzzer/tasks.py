import asyncio
import json
import re
import time
import httpx
from sqlalchemy import select

from src.core.database import AsyncSessionLocal
from .generator import generate_attack_payloads
from .models import FuzzJob, FuzzResult, JobStatus
from .parser import extract_endpoints, resolve_base_url

class GeminiRateLimiter:
    """
    Ensures we do not exceed Gemini's Free Tier limits:
    - ~10 Requests Per Minute (RPM) for gemini-2.5-flash
    """
    def __init__(self, max_rpm=10):
        self.max_rpm = max_rpm
        self.delay_between_requests = 60.0 / max_rpm
        self.last_request_time = 0.0

    async def wait(self):
        now = time.time()
        elapsed = now - self.last_request_time
        if elapsed < self.delay_between_requests:
            sleep_time = self.delay_between_requests - elapsed
            print(f"⏳ Rate limiting Gemini AI... sleeping for {sleep_time:.2f}s")
            await asyncio.sleep(sleep_time)
        
        self.last_request_time = time.time()


gemini_limiter = GeminiRateLimiter(max_rpm=10)


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
            async with httpx.AsyncClient(headers=job.headers) as client:
                response = await client.get(job.openapi_url, timeout=30.0, follow_redirects=True)
                spec = response.json()

            base_url = resolve_base_url(spec, job.openapi_url, job.target_base_url)
            endpoints = extract_endpoints(spec, job.allowed_methods)
            
            http_throttle_delay = 1.0 / max(job.requests_per_second, 1)

            async with httpx.AsyncClient(base_url=base_url, headers=job.headers) as target_client:
                for endpoint in endpoints:
                    
                    # ---> APPLY GEMINI RATE LIMITING HERE <---
                    await gemini_limiter.wait()
                    print(f"🧠 Generating payloads for {endpoint['method']} {endpoint['path']}...")
                    
                    payloads = await generate_attack_payloads(endpoint)

                    if not payloads:
                        continue 

                    for payload in payloads:
                        await asyncio.sleep(http_throttle_delay)

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
                            test_type = payload.get("test_type", "Unknown")
                            print(f"📡 [{status}] {endpoint['method']} {resolved_path} -> {test_type}")

                            # ==========================================
                            # UPGRADED VULNERABILITY DETECTION ENGINE
                            # ==========================================
                            
                            # 1. Did the server crash completely?
                            is_crash = status >= 500

                            # 2. Did a malicious payload unexpectedly succeed?
                            test_type_lower = test_type.lower()
                            critical_attacks = ["sql", "bola", "broken access", "privilege", "idor", "bypass", "nosql", "xss"]
                            is_critical_attack = any(attack in test_type_lower for attack in critical_attacks)
                            
                            unexpected_success = status in [200, 201] and is_critical_attack

                            if is_crash or unexpected_success:
                                vuln_log = FuzzResult(
                                    job_id=job.id,
                                    endpoint_path=endpoint["path"],
                                    http_method=endpoint["method"],
                                    test_type=test_type,
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
            print(f"✅ Job {job.id} completed successfully.")
            return True

        except Exception as e:
            print(f"❌ Job #{job_id} failed with error: {e}")
            job.status = JobStatus.FAILED
            await db.commit()
            return False