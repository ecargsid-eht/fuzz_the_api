from arq import create_pool
from arq.connections import RedisSettings, ArqRedis
from src.core.config import settings


_redis_pool: ArqRedis | None = None

async def init_redis_pool():
    global _redis_pool
    redis_settings = RedisSettings.from_dsn(settings.REDIS_URL)
    _redis_pool = await create_pool(redis_settings)

async def get_redis_pool() -> ArqRedis:
    if _redis_pool is None:
        raise RuntimeError("Redis pool is not initialized")
    return _redis_pool