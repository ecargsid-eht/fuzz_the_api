from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from src.core.config import settings
from src.core.queue import init_redis_pool
from src.modules.fuzzer.router import router as fuzzer_router
from src.modules.auth.router import router as auth_router
from src.core.router import router as main_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_redis_pool() 
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(
    main_router,
    prefix='/api/v1'
)


@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "online",
        "project": settings.PROJECT_NAME
    }