from arq import create_pool
from arq.connections import RedisSettings
from src.core.config import settings


async def get_redis_pool():
    redis_settings = RedisSettings.from_dsn(settings.REDIS_URL)
    return await create_pool(redis_settings)
