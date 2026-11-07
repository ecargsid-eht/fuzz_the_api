from fastapi import APIRouter, Depends, HTTPException, status, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from arq import ArqRedis

from src.core.database import get_db
from src.core.dependencies import get_current_user
from src.core.queue import get_redis_pool
from src.core.security import check_password, generate_access_token, generate_refresh_token
from src.modules.auth import services
from src.modules.auth.schemas import (
    UserCreate, 
    UserResponse, 
    Token, 
    AccessTokenPayload, 
    RefreshTokenPayload,
    OTPVerifyRequest
)

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_in: UserCreate, 
    db: AsyncSession = Depends(get_db),
    redis: ArqRedis = Depends(get_redis_pool)
):
    try:
        existing_user = await services.get_user_by_email(db, user_in.email)
        if existing_user:
            if existing_user.is_verified:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="An account with this email already exists."
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Account exists but is unverified. Please check your email for the OTP."
                )

        new_user = await services.create_user_account(db, user_in)

        await services.generate_and_dispatch_otp(redis, new_user.email)
        return new_user

    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database transaction failed during registration."
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred."
        )


@router.post("/otp/verify", status_code=status.HTTP_200_OK)
async def verify_otp(
    payload: OTPVerifyRequest, 
    db: AsyncSession = Depends(get_db),
    redis: ArqRedis = Depends(get_redis_pool)
):
    try:
        is_valid = await services.verify_and_burn_otp(redis, payload.email, payload.otp)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired OTP."
            )
            
        user = await services.get_user_by_email(db, payload.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )
            
        await services.mark_user_verified(db, user)
        
        return {"message": "Email successfully verified. You can now log in."}

    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while verifying user."
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during verification."
        )


@router.post("/login", response_model=Token)
async def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: AsyncSession = Depends(get_db)
):
    try:
        user = await services.get_user_by_email(db, form_data.username)
        
        if not user or not check_password(form_data.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password.",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        if not user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Please verify your email via the OTP sent to you before logging in."
            )
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This account has been disabled."
            )

        access_token = generate_access_token(
            AccessTokenPayload(id=user.id, email=user.email, role=user.role)
        )
        refresh_token = generate_refresh_token(
            RefreshTokenPayload(id=user.id, email=user.email)
        )

        # await services.update_last_login(db, user) -- later

        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=15 * 24 * 60 * 60 # 15 days
        )
        

        return {
            "access_token": access_token,
            "token_type": "bearer"
        }

    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error during login."
        )
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during login."
        )

@router.post("/refresh", response_model=Token)
async def refresh_access_token(
    response: Response,
    refresh_token: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db)
):
    if not refresh_token:
        raise HTTPException(
            status_code= status.HTTP_401_UNAUTHORIZED,
            detail='Refresh Token missing'
        )
    try:
        tokens = await services.rotate_tokens(db, refresh_token)
        response.set_cookie(
            key="refresh_token",
            value=tokens["refresh_token"],
            httponly=True,
            secure=False, 
            samesite="lax",
            max_age=15 * 24 * 60 * 60
        )
        return {
            "access_token": tokens["access_token"],
            "token_type": "bearer"
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error during token refresh."
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred."
        )

@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(key="refresh_token", httponly=True, samesite="lax")
    return {"message": "Successfully logged out"}

@router.get('/me')
async def get_me(current_user = Depends(get_current_user)):
    return current_user