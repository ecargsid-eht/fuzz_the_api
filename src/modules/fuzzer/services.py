import httpx
import json
from fastapi import HTTPException
from urllib.parse import urlparse, urlunparse
from src.core.database import AsyncSession
from .schemas import ScanRequest
from arq.connections import ArqRedis
from .models import FuzzJob, FuzzResult, JobStatus
from sqlalchemy import select



def normalize_url(url: str):
    if not url.startswith(("http://", "https://")):
        if "localhost" in url or "127.0.0.1" in url:
            url = f"http://{url}"
        else: 
            url = f"https://{url}"

    parsed = urlparse(url)

    if parsed.path.endswith(("/openapi.json", "/swagger.json")):
        return url

    if parsed.path in ["", "/"]:
        new_path='/openapi.json'
    else:
        parts = [p for p in parsed.path.strip("/").split("/") if p]
        if parts:
            parts[-1] = "openapi.json"
            new_path = "/"+"/".join(parts)
        else:
            new_path = "/openapi.json"

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        new_path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))


async def scanRequest(db: AsyncSession, req: ScanRequest, redis: ArqRedis):
    payload = req.model_dump(mode='json')
    target_url = normalize_url(str(payload["openapi_url"]))

    is_local = "localhost" in target_url or "127.0.0.1" in target_url
    timeout_val = 5.0 if is_local else 45.0

    request_headers = {
        "User-Agent": "AgenticFuzzer/1.0",
        **payload.get("headers",{})
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(target_url, timeout=timeout_val, follow_redirects=True, headers=request_headers)
            if response.status_code != 200:
                raise HTTPException(
                    status_code=400,
                    detail=f"Target rejected the request. Status {response.status_code} at {target_url}"
                )
            response.json()
        except httpx.RequestError:
            raise HTTPException(
                status_code=400,
                detail=f"Could not connect to target URL: {target_url}"
            )
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Target URL is reachable, but did not return valid JSON data"
            )
    job = FuzzJob(
        openapi_url=target_url, 
        user_email=str(req.user_email),
        target_base_url=payload.get("target_base_url"),
        headers=payload.get("headers", {}),
        allowed_methods=payload.get("allowed_methods", ["GET"]),
        requests_per_second=payload.get("requests_per_second", 5)
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    await redis.enqueue_job('run_fuzzer', job.id)

    return job.id


async def scanStatus(db: AsyncSession, job_id: int):
    job_result = await db.execute(select(FuzzJob).where(FuzzJob.id == job_id))
    job = job_result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404,detail = "Scan job not found.")

    vuln_result = await db.execute(select(FuzzResult).where(FuzzResult.job_id == job_id))
    vulnerabilities = vuln_result.scalars().all()
    return job, vulnerabilities


async def generate_report(db: AsyncSession, job_id: int):
    """
    Fetches the scan job and vulnerabilities, and builds a Markdown security report.
    Returns None if the job is not found.
    """
    # 1. Fetch the Job
    job_result = await db.execute(select(FuzzJob).where(FuzzJob.id == job_id))
    job = job_result.scalar_one_or_none()
    
    if not job:
        return None

    # 2. Fetch the Vulnerabilities
    vuln_result = await db.execute(select(FuzzResult).where(FuzzResult.job_id == job_id))
    vulnerabilities = vuln_result.scalars().all()

    # 3. Build the Markdown Content
    md_lines = [
        "# 🛡️ Automated API Security Audit Report",
        f"**Target API:** `{job.openapi_url}`\n",
        f"**Scan Status:** `{job.status}`\n",
        f"**Total Vulnerabilities Found:** `{len(vulnerabilities)}`\n",
        "---\n",
        "## 🚨 Executive Summary",
    ]

    if not vulnerabilities:
        md_lines.append("No critical vulnerabilities (Unhandled 500s or 200/201 Bypasses) were detected during this scan. The API successfully handled all malicious payloads gracefully.")
    else:
        md_lines.append("The following critical vulnerabilities were identified during the automated fuzzing process. Immediate remediation is recommended.\n")
        md_lines.append("---\n## 📋 Detailed Findings\n")

        for idx, vuln in enumerate(vulnerabilities, 1):
            md_lines.extend([
                f"### {idx}. {vuln.test_type.upper()} on `{vuln.endpoint_path}`",
                f"- **HTTP Method:** `{vuln.http_method}`",
                f"- **Target Response Code:** `{vuln.status_code}`",
                "",
                "**Malicious Payload Sent:**",
                "```json",
                json.dumps(vuln.payload_sent, indent=2),
                "```",
                "",
                "**Server Response Snippet:**",
                "```text",
                vuln.response_body,
                "```",
                "---\n"
            ])

    return "\n".join(md_lines)


