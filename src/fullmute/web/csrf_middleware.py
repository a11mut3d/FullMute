from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response
from typing import List, Optional
import re
import time

from fullmute.web.csrf import get_csrf_manager
from fullmute.utils.logger import setup_logger

logger = setup_logger()


class CSRFMiddleware(BaseHTTPMiddleware):

    
    STATE_CHANGING_METHODS = {'POST', 'PUT', 'DELETE', 'PATCH'}

    
    EXCLUDED_PATHS = [
        '/api/auth/login',  
        '/api/',            
        '/docs',
        '/redoc',
        '/openapi.json',
        '/static/',         
    ]

    def __init__(self, app, secret_key: Optional[str] = None):
        super().__init__(app)
        self.csrf_manager = get_csrf_manager(secret_key)
        
        
        self._valid_tokens: dict = {}
        self._cache_ttl = 300  

    async def dispatch(self, request, call_next):
        
        if request.method not in self.STATE_CHANGING_METHODS:
            return await call_next(request)

        
        path = request.url.path
        for excluded in self.EXCLUDED_PATHS:
            if path.startswith(excluded):
                return await call_next(request)

        
        csrf_token = self._get_csrf_token(request)

        
        if not csrf_token:
            logger.warning(f"CSRF token missing for {request.method} {path}")
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token missing. Please refresh the page and try again."}
            )

        
        user_id = self._get_user_id(request)

        if not user_id:
            
            return await call_next(request)

        
        if not self._validate_token_cached(csrf_token, user_id):
            logger.warning(f"Invalid CSRF token for {request.method} {path} (user {user_id})")
            return JSONResponse(
                status_code=403,
                content={"detail": "Invalid CSRF token. Please refresh the page and try again."}
            )

        
        return await call_next(request)

    def _get_csrf_token(self, request) -> Optional[str]:
        
        token = request.headers.get('X-CSRF-Token')
        if token:
            return token

        token = request.headers.get('X-XSRF-TOKEN')
        if token:
            return token

        token = request.cookies.get('csrf_token')
        if token:
            return token

        return None

    def _get_user_id(self, request) -> Optional[int]:
        import jwt
        from fullmute.web.config import config

        token = request.cookies.get('access_token')
        if not token:
            
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header[7:]

        if not token:
            return None

        try:
            payload = jwt.decode(
                token,
                config.secret_key,
                algorithms=["HS256"]
            )
            return int(payload.get('sub'))
        except (jwt.InvalidTokenError, ValueError):
            return None

    def _validate_token_cached(self, token: str, user_id: int) -> bool:
        cache_key = f"{token}:{user_id}"
        
        
        if cache_key in self._valid_tokens:
            cached_time, result = self._valid_tokens[cache_key]
            if time.time() - cached_time < self._cache_ttl:
                return result
            else:
                
                del self._valid_tokens[cache_key]

        
        is_valid = self.csrf_manager.validate_token(token, user_id)
        
        
        self._valid_tokens[cache_key] = (time.time(), is_valid)
        
        
        if len(self._valid_tokens) > 1000:
            self._cleanup_cache()

        return is_valid

    def _cleanup_cache(self):
        now = time.time()
        expired = [
            key for key, (cached_time, _) in self._valid_tokens.items()
            if now - cached_time > self._cache_ttl
        ]
        for key in expired:
            del self._valid_tokens[key]


def setup_csrf_protection(app, secret_key: str):
    app.add_middleware(CSRFMiddleware, secret_key=secret_key)
    logger.info("CSRF protection enabled")
