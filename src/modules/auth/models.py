from datetime import datetime
import enum
from sqlalchemy import String, Boolean, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import List, Optional, TYPE_CHECKING
from src.core.database import Base

if TYPE_CHECKING:
    from ..fuzzer.models import FuzzJob

class UserRole(str, enum.Enum):
    OPERATOR = "operator"  # Standard user running scans
    ADMIN = "admin"        # System administrator

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String)
    full_name: Mapped[str] = mapped_column(String(255))
    
    role: Mapped[UserRole] = mapped_column(default=UserRole.OPERATOR)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    jobs: Mapped[List["FuzzJob"]] = relationship(
        back_populates="owner", 
        cascade="all, delete-orphan"
    )