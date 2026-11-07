import httpx
import json
import tempfile
import os
from fastapi import HTTPException, status
from urllib.parse import urlparse, urlunparse
from sqlalchemy import select, func
from sqlalchemy.exc import SQLAlchemyError
from arq.connections import ArqRedis
from markdown_pdf import MarkdownPdf, Section

from src.core.database import AsyncSession
from .schemas import ScanRequest
from .models import FuzzJob, FuzzResult, JobStatus
from .network import safe_fetch_url, validate_safe_url

def normalize_url(url: str) -> str:
    url_str = str(url).strip()
    if not url_str.startswith(("http://", "https://")):
        url_str = f"https://{url_str}"

    parsed = urlparse(url_str)

    if parsed.path.endswith((".json", ".yaml", ".yml")):
        return url_str

    if parsed.path in ["", "/"]:
        new_path = '/openapi.json'
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            new_path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        
    return url_str

async def getScans(db: AsyncSession, user_id:int):
    query = (
            select(
                FuzzJob.id,
                FuzzJob.openapi_url,
                FuzzJob.target_base_url,
                FuzzJob.status,
                FuzzJob.created_at,
                func.count(FuzzResult.id).label("vulnerabilities_found")
            )
            .outerjoin(FuzzResult, (FuzzResult.job_id == FuzzJob.id) & (FuzzResult.is_vulnerable == True))
            .where(FuzzJob.user_id == user_id)
            .group_by(FuzzJob.id)
            .order_by(FuzzJob.created_at.desc())
        )
    result = await db.execute(query)
        
        # Format the data exactly as the React frontend expects
    scans = []
    for row in result.all():
        scans.append({
            "id": row.id,
            "target_base_url": row.target_base_url or str(row.openapi_url),
            "openapi_url": str(row.openapi_url),
            "status": row.status,
            "vulnerabilities_found": row.vulnerabilities_found,
            "created_at": row.created_at
        })
    return scans


async def scanRequest(db: AsyncSession, req: ScanRequest, redis: ArqRedis, user_id: int):
    payload = req.model_dump(mode='json')
    
    target_url = await validate_safe_url(normalize_url(str(payload["openapi_url"])))
    if payload.get("target_base_url"):
        await validate_safe_url(payload["target_base_url"])

    request_headers = {
        "User-Agent": "AgenticFuzzer/1.0",
        **payload.get("headers",{})
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(target_url, timeout=45.0, follow_redirects=True, headers=request_headers)
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
    # print(target_url, user_id, payload.get("target_base_url"), payload.get("headers"), payload.get("allowed_methods"), payload.get("requests_per_second"))
    job = FuzzJob(
        openapi_url=target_url, 
        user_id=user_id,

        target_base_url=payload.get("target_base_url"),
        headers=payload.get("headers", {}),
        allowed_methods=payload.get("allowed_methods", ["GET"]),
        requests_per_second=payload.get("requests_per_second", 5)
    )
    
    db.add(job)
    
    try:
        await db.flush()
        await redis.enqueue_job('run_fuzzer', job.id, _queue_name="arq:fuzz_queue")
        await db.commit()
        await db.refresh(job)
        return job.id
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error while saving scan job. {str(e)}")
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to queue background job: {str(e)}")

async def scanStatus(db: AsyncSession, job_id: int, user_id: int):
    job_result = await db.execute(select(FuzzJob).where(FuzzJob.id == job_id, FuzzJob.user_id == user_id))
    job = job_result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404,detail = "Scan job not found or unauthorized.")

    vuln_result = await db.execute(select(FuzzResult).where(FuzzResult.job_id == job_id))
    vulnerabilities = vuln_result.scalars().all()
    return job, vulnerabilities

async def generate_report(db: AsyncSession, job_id: int, user_id: int):
    job_result = await db.execute(select(FuzzJob).where(FuzzJob.id == job_id, FuzzJob.user_id == user_id))
    job = job_result.scalar_one_or_none()
    
    if not job:
        return None

    if job.status != JobStatus.COMPLETED:
        raise ValueError(f"Scan is currently {job.status.value}. Reports are only available upon completion.")

    vuln_result = await db.execute(select(FuzzResult).where(FuzzResult.job_id == job_id))
    vulnerabilities = vuln_result.scalars().all()

    md_lines = [
        "# 🛡️ Automated API Security Audit Report",
        f"**Target API:** `{job.openapi_url}`\n",
        f"**Scan Status:** `{job.status._value_}`\n",
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

async def trigger_email_report(db: AsyncSession, job_id: int, email: str, arq_redis: ArqRedis, user_id: int) -> bool:
    job_result = await db.execute(select(FuzzJob).where(FuzzJob.id == job_id, FuzzJob.user_id == user_id))
    if not job_result.scalar_one_or_none():
        return False

    await arq_redis.enqueue_job(
        "send_email_task",
        job_id=job_id,
        target_email=email,
        _queue_name="arq:email_queue"
    )
    return True

async def generate_pdf_report(db: AsyncSession, job_id: int, user_id: int) -> str | None:
    report_content = await generate_report(db, job_id, user_id)
    
    if report_content is None:
        return None

    fd, temp_pdf_path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)

    try:
        pdf = MarkdownPdf(toc_level=2)
        pdf.add_section(Section(report_content, toc=False)) 
        pdf.save(temp_pdf_path) 
        return temp_pdf_path

    except Exception as e:
        if os.path.exists(temp_pdf_path):
            os.remove(temp_pdf_path)
        raise e