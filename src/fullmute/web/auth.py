import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict
from functools import wraps

from fastapi import Request, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from fullmute.web.database import authenticate_user, get_user_by_id, log_access
from fullmute.web.config import config
from fullmute.utils.logger import setup_logger

logger = setup_logger()

security = HTTPBearer(auto_error=False)


def create_access_token(user_data: Dict) -> str:
    expire = datetime.utcnow() + timedelta(hours=config.token_expire_hours)
    to_encode = {
        "exp": expire,
        "sub": str(user_data['id']),
        "username": user_data['username'],
        "role": user_data['role'],
        "organization_id": user_data.get('organization_id', 1)
    }
    return jwt.encode(to_encode, config.secret_key, algorithm="HS256")


def decode_access_token(token: str) -> Optional[Dict]:
    try:
        payload = jwt.decode(token, config.secret_key, algorithms=["HS256"])
        return {
            'id': int(payload['sub']),
            'username': payload['username'],
            'role': payload['role'],
            'organization_id': payload.get('organization_id', 1)
        }
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    request: Request = None
) -> Dict:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    user_data = decode_access_token(token)
    
    if user_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    
    if request:
        log_access(
            user_id=user_data['id'],
            action="API Access",
            resource=request.url.path,
            ip_address=request.client.host if request.client else None
        )
    
    return user_data


def require_role(required_role: str):
    def role_checker(current_user: Dict = Depends(get_current_user)):
        
        if current_user['role'] == 'admin':
            return current_user
        
        if required_role == 'scanner' and current_user['role'] in ['scanner', 'admin']:
            return current_user
        
        if current_user['role'] == required_role:
            return current_user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    return role_checker


async def get_optional_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Optional[Dict]:
    from fullmute.utils.logger import setup_logger
    logger = setup_logger()
    
    token = None
    
    
    if credentials and credentials.credentials:
        token = credentials.credentials
        logger.debug(f"Got token from Authorization header")
    else:
        
        token = request.cookies.get("access_token")
        if token:
            logger.debug(f"Got token from cookie")
        else:
            logger.debug("No token found in header or cookie")
            logger.debug(f"Cookies: {request.cookies}")
    
    if not token:
        return None

    user_data = decode_access_token(token)
    
    if user_data:
        logger.debug(f"User authenticated: {user_data['username']}")
    else:
        logger.debug("Token decoding failed")
    
    return user_data


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict:
    token = None
    
    
    if credentials and credentials.credentials:
        token = credentials.credentials
    else:
        
        token = request.cookies.get("access_token")
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_data = decode_access_token(token)

    if user_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    
    log_access(
        user_id=user_data['id'],
        action="API Access",
        resource=request.url.path,
        ip_address=request.client.host if request.client else None
    )

    return user_data
