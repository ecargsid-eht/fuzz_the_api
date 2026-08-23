
from fastapi import APIRouter, Depends, HTTPException, Response
from arq.connections import ArqRedis
from src.core.queue import get_redis_pool
from src.core.database import AsyncSession, get_db
from . import services
from .schemas import ScanRequest
from .models import FuzzJob, FuzzResult
from sqlalchemy import select

router = APIRouter()

@router.post('/scans', status_code=201)
async def scanRequest(req: ScanRequest, db: AsyncSession = Depends(get_db), redis:ArqRedis = Depends(get_redis_pool)):
    try:
        scan_id = await services.scanRequest(db, req, redis)
        return {
            "message":"Scan queued successfully.",
            "job_id":scan_id,
            "status_url": f"/api/v1/fuzzer/scans/{scan_id}"
        }

    except Exception as e:
        raise HTTPException(status_code=505, detail = str(e))

@router.get('/scans/{job_id}')
async def getScanStatus(job_id:int, db: AsyncSession= Depends(get_db)):
    try:
        job, vulnerabilities = await services.scanStatus(db, job_id)
        return {
            "job_id": job_id,
            "target":job.openapi_url,
            "status":job.status,
            "vulnerability_found":len(vulnerabilities),
            "results":[
                {
                    "endpoint": vuln.endpoint_path,
                    "method": vuln.http_method,
                    "test_type": vuln.test_type,
                    "payload": vuln.payload_sent,
                    "target_response_code": vuln.status_code,
                    "response_snippet": vuln.response_body
                }
                for vuln in vulnerabilities
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=505, detail=str(e))

@router.get("/scans/{job_id}/report", summary="Download Security Audit Report")
async def download_scan_report(
    job_id: int, 
    db: AsyncSession = Depends(get_db)
):
    report_content = await services.generate_report(db, job_id)
    
    if report_content is None:
        raise HTTPException(status_code=404, detail="Scan job not found.")

    return Response(
        content=report_content,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f"attachment; filename=security_report_job_{job_id}.md"
        }
    )