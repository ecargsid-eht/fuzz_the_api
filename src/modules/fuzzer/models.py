import enum
from sqlalchemy import String, Integer, BigInteger, JSON, Text
from typing import Optional
from sqlalchemy.orm import Mapped, mapped_column
from src.core.database import Base

class JobStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class FuzzJob(Base):
    __tablename__ = "fuzzing_jobs"

    id: Mapped[str] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    openpi_url: Mapped[str] = mapped_column(String)
    user_email: Mapped[str] = mapped_column(String)
    status: Mapped[JobStatus] = mapped_column(default=JobStatus.QUEUED)


class FuzzResult(Base):
    __tablename__ = "fuzz_results"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(String, index=True)
    endpoint: Mapped[str] = mapped_column(String)

    payload_sent: Mapped[dict] = mapped_column(JSON)
    status_code: Mapped[int] = mapped_column(Integer)
    response_body: Mapped[Optional[str]] = mapped_column(Text,nullable=True)
    is_vulnerable: Mapped[bool] = mapped_column(default=False)

    