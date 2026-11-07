from fastapi import APIRouter
from ..modules.auth.router import router as auth_router
from ..modules.fuzzer.router import router as fuzzer_router
router = APIRouter()

router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
router.include_router(fuzzer_router, prefix="/fuzzer", tags=["Fuzzer"])