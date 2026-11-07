from fastapi import APIRouter, Depends, HTTPException, Response, BackgroundTasks, status
from fastapi.responses import FileResponse
import os
from arq.connections import ArqRedis
from pydantic import EmailStr
from typing import List
from src.core.queue import get_redis_pool
from src.core.database import AsyncSession, get_db
from . import services
from .schemas import ScanRequest, ScanResponse
from src.modules.auth.models import User
from src.core.dependencies import get_current_user 

router = APIRouter()

@router.get('/scans', response_model=List[ScanResponse], status_code=status.HTTP_200_OK)
async def getScans(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        scans = await services.getScans(db, current_user.id)
        return scans
    except HTTPException:
        raise
    except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail = str(e))
    
@router.post('/scans', status_code=status.HTTP_201_CREATED)
async def scanRequest(
    req: ScanRequest, 
    db: AsyncSession = Depends(get_db), 
    redis: ArqRedis = Depends(get_redis_pool),
    current_user: User = Depends(get_current_user) 
):
    try:
        scan_id = await services.scanRequest(db, req, redis, current_user.id)
        return {
            "message":"Scan queued successfully.",
            "job_id":scan_id,
            "status_url": f"/api/v1/fuzzer/scans/{scan_id}"
        }
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        print(str(e))
        raise HTTPException(status_code=500, detail = str(e))

@router.get('/scans/{job_id}')
async def getScanStatus(
    job_id: int, 
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        job, vulnerabilities = await services.scanStatus(db, job_id, current_user.id)
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
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scans/{job_id}/report", summary="Download Security Audit Report")
async def download_scan_report(
    job_id: int, 
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user) 
):
    try:
        # EDITED: Pass current_user.id
        report_content = await services.generate_report(db, job_id, current_user.id)
        
        if report_content is None:
            raise HTTPException(status_code=404, detail="Scan job not found.")

        return Response(
            content=report_content,
            media_type="text/markdown",
            headers={
                "Content-Disposition": f"attachment; filename=security_report_job_{job_id}.md"
            }
        )
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error generating report.")

@router.post("/scans/{job_id}/email-report", summary="Email Security Audit Report")
async def email_scan_report(
    job_id: int, 
    email: EmailStr,
    db: AsyncSession = Depends(get_db),
    arq_redis: ArqRedis = Depends(get_redis_pool),
    current_user: User = Depends(get_current_user) 
):
    success = await services.trigger_email_report(db, job_id, email, arq_redis, current_user.id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Scan job not found.")

    return {"message": f"Security report successfully queued. An email will be dispatched to {email} shortly."}

@router.get("/scans/{job_id}/report/pdf", summary="Download Security Audit as PDF")
async def download_scan_report_pdf(
    job_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        temp_pdf_path = await services.generate_pdf_report(db, job_id, current_user.id)
        
        if temp_pdf_path is None:
            raise HTTPException(status_code=404, detail="Scan job not found.")

        background_tasks.add_task(os.remove, temp_pdf_path)

        return FileResponse(
            path=temp_pdf_path,
            media_type="application/pdf",
            filename=f"security_report_job_{job_id}.pdf",
            headers={"Content-Disposition": f"attachment; filename=security_report_job_{job_id}.pdf"}
        )
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")