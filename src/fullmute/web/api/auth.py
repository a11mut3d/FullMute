from fastapi import APIRouter, Depends, HTTPException, status, Form, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from datetime import timedelta
import os
import json

from fullmute.web.auth import create_access_token, get_current_user, require_role
from fullmute.web.database import (
    authenticate_user, create_user, generate_api_key,
    list_users, regenerate_api_key, get_user_by_id, log_access, get_db_connection
)
from fullmute.web.rate_limiter import check_rate_limit
from fullmute.web.csrf import get_csrf_manager

router = APIRouter()


class LoginRequest(BaseModel):
    api_key: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict = None
    grace_period_warning: bool = False
    grace_period_ends: str = None
    message: str = None


class APIKeyResponse(BaseModel):
    api_key: str
    message: str = "API key regenerated successfully"


def get_client_ip(request: Request) -> str:
    
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    
    if request.client:
        return request.client.host
    
    return "unknown"


@router.post("/login", response_model=LoginResponse)
async def login(request: Request, api_key: str = Form(None)):
    from fullmute.web.database import log_access
    
    
    client_ip = get_client_ip(request)
    
    
    is_limited, retry_after = check_rate_limit(
        client_id=f"login:{client_ip}",
        endpoint="login"
    )
    
    if is_limited:
        
        log_access(
            user_id=None,
            action="Login rate limit exceeded",
            resource="/api/auth/login",
            ip_address=client_ip,
            status_code=429
        )
        
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)}
        )
    
    
    log_access(
        user_id=None,
        action="Login attempt",
        resource="/api/auth/login",
        ip_address=client_ip,
        status_code=None
    )
    
    
    if not api_key:
        try:
            
            body = await request.json()
            api_key = body.get('api_key')
        except (json.JSONDecodeError, Exception):
            pass
    
    
    if not api_key:
        log_access(
            user_id=None,
            action="Login failed - no API key provided",
            resource="/api/auth/login",
            ip_address=client_ip,
            status_code=400
        )
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="API key is required"
        )
    
    user = authenticate_user(api_key)

    if not user:
        
        log_access(
            user_id=None,
            action="Login failed - invalid API key",
            resource="/api/auth/login",
            ip_address=client_ip,
            status_code=401
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    
    if user.get('in_grace_period'):
        
        grace_period_ends = user.get('grace_period_ends', 'unknown')
        logger.warning(f"User {user['username']} logged in during grace period (ends: {grace_period_ends})")

        
        access_token = create_access_token(user)

        
        csrf_manager = get_csrf_manager()
        csrf_token = csrf_manager.generate_token(user_id=user['id'])

        log_access(
            user_id=user['id'],
            action="Login success (grace period)",
            resource="/api/auth/login",
            ip_address=client_ip,
            status_code=200
        )

        
        is_production = os.getenv('FULLMUTE_PRODUCTION', 'false').lower() == 'true'

        response = JSONResponse(
            content={
                "access_token": access_token,
                "token_type": "bearer",
                "grace_period_warning": True,
                "grace_period_ends": grace_period_ends,
                "message": f"Your API key has expired. You have until {grace_period_ends} to renew. After that, your account will be deleted.",
                "csrf_token": csrf_token  
            }
        )

        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=is_production,
            samesite="lax",
            max_age=int(config.token_expire_hours) * 3600
        )

        
        response.set_cookie(
            key="csrf_token",
            value=csrf_token,
            httponly=False,  
            secure=is_production,
            samesite="lax",
            max_age=int(config.token_expire_hours) * 3600,
            path="/"
        )

        return response

    access_token = create_access_token(user)

    
    csrf_manager = get_csrf_manager()
    csrf_token = csrf_manager.generate_token(user_id=user['id'])

    
    log_access(
        user_id=user['id'],
        action="Login successful",
        resource="/api/auth/login",
        ip_address=client_ip,
        status_code=200
    )

    
    is_production = os.getenv('FULLMUTE_PRODUCTION', 'false').lower() == 'true'

    response = JSONResponse(
        content={
            "access_token": access_token,
            "token_type": "bearer",
            "user": user,
            "csrf_token": csrf_token  
        }
    )

    
    
    secure_cookie = is_production and os.getenv('FULLMUTE_SECURE_COOKIE', 'true').lower() == 'true'

    response.set_cookie(
        key="access_token",
        value=access_token,
        max_age=int(timedelta(hours=24).total_seconds()),
        httponly=True,  
        samesite="lax",  
        secure=secure_cookie,  
        path="/",
        domain=None  
    )

    
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,  
        secure=secure_cookie,  
        samesite="lax",
        max_age=int(timedelta(hours=24).total_seconds()),
        path="/"
    )

    
    response.headers["X-RateLimit-Limit"] = "5"
    response.headers["X-RateLimit-Remaining"] = "4"
    response.headers["X-RateLimit-Window"] = "60"

    return response


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    user_data = get_user_by_id(current_user['id'])
    return user_data


@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    log_access(
        user_id=current_user['id'],
        action="Logout"
    )
    return {"message": "Logged out successfully"}


@router.get("/users", dependencies=[Depends(require_role("admin"))])
async def list_all_users(
    current_user: dict = Depends(get_current_user)
):
    if current_user['role'] == 'admin':
        return list_users(organization_id=None)
    else:
        return list_users(organization_id=current_user['organization_id'])


@router.delete("/users/{user_id}", dependencies=[Depends(require_role("admin"))])
async def delete_user_endpoint(
    user_id: int,
    current_user: dict = Depends(get_current_user)
):
    from fullmute.web.database import delete_user
    
    
    if user_id == current_user['id']:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete yourself"
        )
    
    success = delete_user(user_id)
    
    if success:
        return {"message": "User deleted successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )


@router.post("/users/{user_id}/set-expiry", dependencies=[Depends(require_role("admin"))])
async def set_user_expiry(
    user_id: int,
    expires_at: str = Form(...),  
    current_user: dict = Depends(get_current_user)
):
    from fullmute.web.database import update_user_expires
    
    success = update_user_expires(user_id, expires_at + " 23:59:59")
    
    if success:
        return {"message": f"User expiration set to {expires_at}"}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )


@router.post("/users", dependencies=[Depends(require_role("admin"))])
async def create_new_user(username: str = Form(...), role: str = Form("viewer")):
    api_key = generate_api_key()
    user_id = create_user(username=username, api_key=api_key, role=role)
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    return {
        "id": user_id,
        "username": username,
        "role": role,
        "api_key": api_key
    }


@router.post("/users/{user_id}/regenerate-key", dependencies=[Depends(require_role("admin"))])
async def regenerate_user_key(user_id: int):
    new_key = regenerate_api_key(user_id)

    if not new_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return APIKeyResponse(api_key=new_key)


@router.post("/users/{user_id}/extend-token", dependencies=[Depends(require_role("admin"))])
async def extend_user_token(
    user_id: int,
    days: int = Form(30)  
):
    from datetime import datetime, timedelta
    from fullmute.web.database import get_user_by_id, get_db_connection
    
    
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    
    if user.get('expires_at'):
        
        new_expires = datetime.utcnow() + timedelta(days=days)
    else:
        
        new_expires = datetime.utcnow() + timedelta(days=days)
    
    new_expires_str = new_expires.strftime("%Y-%m-%d %H:%M:%S")
    
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET expires_at = ? WHERE id = ?",
            (new_expires_str, user_id)
        )
        conn.commit()
        
        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to extend token"
            )
    
    return {
        "message": f"Token extended for {days} days",
        "user_id": user_id,
        "username": user['username'],
        "new_expires_at": new_expires_str
    }


@router.post("/users/{user_id}/set-token-expiry", dependencies=[Depends(require_role("admin"))])
async def set_user_token_expiry(
    user_id: int,
    expires_at: str = Form(...)  
):
    from datetime import datetime
    import re
    
    
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    
    if not re.match(r'^\d{4}-\d{2}-\d{2}$', expires_at):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid date format. Use YYYY-MM-DD"
        )
    
    
    try:
        expiry_date = datetime.strptime(expires_at, "%Y-%m-%d")
        if expiry_date < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Expiration date cannot be in the past"
            )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid date"
        )
    
    
    expires_full = f"{expires_at} 23:59:59"
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET expires_at = ? WHERE id = ?",
            (expires_full, user_id)
        )
        conn.commit()
        
        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to set token expiry"
            )
    
    return {
        "message": f"Token expiry set to {expires_at}",
        "user_id": user_id,
        "username": user['username'],
        "expires_at": expires_full
    }
