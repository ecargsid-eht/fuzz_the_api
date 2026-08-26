from arq.connections import RedisSettings
from src.core.config import settings
from src.modules.fuzzer.tasks import run_fuzzer, send_email_task

class FuzzWorkerSettings:
    functions = [run_fuzzer]
    queue_name = "arq:fuzz_queue"
    redis_settings = RedisSettings.from_dsn(settings.REDIS_URL)
    max_jobs = 2

class EmailWorkerSettings:
    functions = [send_email_task]
    redis_settings = RedisSettings.from_dsn(settings.REDIS_URL)
    queue_name = "arq:email_queue"
    max_jobs = 10