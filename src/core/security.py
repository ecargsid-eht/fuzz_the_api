import bcrypt
from datetime import datetime, timezone, timedelta
from typing import Any, Dict
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from src.core.config import settings
from src.modules.auth.schemas import AccessTokenPayload, RefreshTokenPayload

SECRET = settings.JWT_SECRET

def hash_password(password: str) -> str:
    pwbyte = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwbyte, salt)
    return hashed.decode('utf-8')

def check_password(password: str, hashed: str) -> bool:
    pwbytes = password.encode('utf-8')
    hashbytes = hashed.encode('utf-8')
    return bcrypt.checkpw(pwbytes, hashbytes)

def generate_access_token(data: AccessTokenPayload) -> str:
    to_encode = data.model_dump(mode='json')
    minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    expire = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    
    to_encode.update({
        "exp": expire, 
        "type": "access"
    })
    return jwt.encode(to_encode, SECRET, algorithm="HS256")

def generate_refresh_token(data: RefreshTokenPayload) -> str:
    to_encode = data.model_dump(mode='json')
    minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 1440
    expire = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    
    to_encode.update({
        "exp": expire, 
        "type": "refresh"
    })
    return jwt.encode(to_encode, SECRET, algorithm="HS256")
    
def verify_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        if payload.get("type") == "refresh":
            raise ValueError("Refresh Token intended to use as Access Token.")
        return payload
    except ExpiredSignatureError:
        raise ValueError("Expired Token used.")
    except InvalidTokenError:
        raise ValueError("Invalid access token used.")

def verify_refresh_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        if payload.get("type") != "refresh":
            raise ValueError("The token is not a refresh token.")
        return payload
    except ExpiredSignatureError:   
        raise ValueError("Refresh token expired. Please log in again.")
    except InvalidTokenError:
        raise ValueError("Invalid refresh token. Please log in again.")