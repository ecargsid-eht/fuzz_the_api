import logging
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncAttrs, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from .config import settings

DATABASE_URL = settings.DATABASE_URL
logger = logging.getLogger('backend')

try:
    engine = create_async_engine(DATABASE_URL, echo=True, pool_size=20, max_overflow=20, pool_pre_ping=True)
except Exception as e:
    logger.error(f'Database engine creation failed with DATABASE URL: {DATABASE_URL}. Error:\n {e}')
    raise e

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    autoflush=False,
    expire_on_commit=False
)

class Base(AsyncAttrs, DeclarativeBase):
    pass

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()