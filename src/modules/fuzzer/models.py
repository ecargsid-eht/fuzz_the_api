import enum
from sqlalchemy import String, Integer, BigInteger, JSON, Text, ForeignKey
from typing import Optional, Any
from sqlalchemy.orm import Mapped, mapped_column
from src.core.database import Base

class JobStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class FuzzJob(Base):
    __tablename__ = "fuzzing_jobs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    openapi_url: Mapped[str] = mapped_column(String)
    user_email: Mapped[str] = mapped_column(String)
    status: Mapped[JobStatus] = mapped_column(default=JobStatus.QUEUED)

    target_base_url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    headers: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    allowed_methods: Mapped[list[str]] = mapped_column(JSON, default=lambda: ["GET"])
    requests_per_second: Mapped[int] = mapped_column(Integer, default=5)


class FuzzResult(Base):
    __tablename__ = "fuzz_results"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    job_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("fuzzing_jobs.id", ondelete="CASCADE"))
    endpoint_path: Mapped[str] = mapped_column(String, nullable=False)
    http_method: Mapped[str] = mapped_column(String, nullable=False)
    test_type: Mapped[str] = mapped_column(String, nullable=False)
    payload_sent: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    response_body: Mapped[Optional[str]] = mapped_column(Text,nullable=True)
    is_vulnerable: Mapped[bool] = mapped_column(default=False)

    