from arq.connections import RedisSettings
from src.core.config import settings
from src.modules.fuzzer.tasks import run_fuzzer

class WorkerSettings:
    functions = [run_fuzzer]
    redis_settings = RedisSettings.from_dsn(settings.REDIS_URL)