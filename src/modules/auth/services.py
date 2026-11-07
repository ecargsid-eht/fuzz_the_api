import secrets
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from arq import ArqRedis
from src.core.security import verify_refresh_token, generate_access_token, generate_refresh_token
from src.modules.auth.schemas import AccessTokenPayload, RefreshTokenPayload
from src.modules.auth.models import User
from src.modules.auth.schemas import UserCreate
from src.core.security import hash_password



async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()

async def get_user_by_id(db: AsyncSession, user_id: int) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()

async def create_user_account(db: AsyncSession, user_in: UserCreate) -> User:
    new_user = User(
        email=user_in.email,
        full_name=user_in.full_name,
        hashed_password=hash_password(user_in.password),
        is_verified=False
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user) 
    
    return new_user

async def send_otp_email(email: str, otp: str):
    """
    Placeholder for the actual email dispatch logic.
    Integrate aiosmtplib, SendGrid, or AWS SES here.
    """
    # TODO: Replace with actual SMTP/API email dispatch
    print(f"[EMAIL MOCK] 📧 Sending OTP {otp} to {email}")

async def generate_and_dispatch_otp(redis: ArqRedis, email: str) -> None:
    otp = "".join(str(secrets.randbelow(10)) for _ in range(6))
    print(otp)
    redis_key = f"auth:otp:{email}"
    await redis.setex(redis_key, 600, otp)
    
    await redis.enqueue_job(
        'send_otp_email', 
        email, 
        otp, 
        _queue_name="arq:email_queue"
    )

async def verify_and_burn_otp(redis: ArqRedis, email: str, provided_otp: str) -> bool:
    redis_key = f"auth:otp:{email}"
    stored_otp = await redis.get(redis_key)
    
    if stored_otp and stored_otp.decode("utf-8") == provided_otp:
        await redis.delete(redis_key) 
        return True
        
    return False

async def mark_user_verified(db: AsyncSession, user: User) -> None:
    user.is_verified = True
    await db.commit()

async def rotate_tokens(db: AsyncSession, refresh_token: str) -> dict:
    token_data = verify_refresh_token(refresh_token)
    user_id = token_data.get("id")
    
    user = await get_user_by_id(db, user_id)
    
    if not user:
        raise ValueError("User no longer exists.")
        
    if not user.is_active:
        raise ValueError("This account has been disabled.")

    access_payload = AccessTokenPayload(id=user.id, email=user.email, role=user.role)
    refresh_payload = RefreshTokenPayload(id=user.id, email=user.email)

    new_access_token = generate_access_token(access_payload)
    new_refresh_token = generate_refresh_token(refresh_payload)

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }