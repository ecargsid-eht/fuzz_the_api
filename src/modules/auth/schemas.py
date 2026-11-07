from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from .models import UserRole

class UserBase(BaseModel):
    email: EmailStr
    full_name: str = Field(..., min_length=2, max_length=255)

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, description="Must be at least 8 characters")

class AccessTokenPayload(BaseModel):
    id: int
    email: EmailStr
    role: UserRole


class RefreshTokenPayload(BaseModel):
    id: int

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class UserResponse(UserBase):
    id: int
    role: UserRole
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login: datetime | None = None

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    id: int | None = None
    email: str | None = None
    role: UserRole | None = None

class OTPVerifyRequest(BaseModel): 
    email: EmailStr
    otp: str