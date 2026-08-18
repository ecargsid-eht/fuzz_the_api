from fastapi import FastAPI
import os
from src.core.config import settings
from src.modules.fuzzer.router import router as fuzzer_router




app = FastAPI(
    title=settings.PROJECT_NAME
)

app.include_router(
    fuzzer_router,
    prefix="/api/v1/fuzzer"
)

@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "online",
        "project": settings.PROJECT_NAME
    }