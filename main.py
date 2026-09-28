from fastapi import FastAPI
from contextlib import asynccontextmanager
from src.core.queue import init_redis_pool
import os
from src.core.config import settings
from src.modules.fuzzer.router import router as fuzzer_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_redis_pool() # Starts the single pool on boot
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    lifespan=lifespan
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