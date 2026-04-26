import secrets
import hashlib
from typing import Optional, Dict
from datetime import datetime, timedelta
from threading import Lock


class CSRFTokenManager:
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or secrets.token_hex(32)
        self._tokens: Dict[str, Dict] = {}
        self._lock = Lock()
        self._token_ttl = timedelta(hours=24)
    
    def generate_token(self, user_id: int, session_id: str = None) -> str:
        timestamp = datetime.utcnow().isoformat()
        random_part = secrets.token_hex(16)
        
        
        token_data = f"{user_id}:{timestamp}:{random_part}"
        if session_id:
            token_data += f":{session_id}"
        
        
        token_hash = hashlib.sha256(
            f"{token_data}:{self.secret_key}".encode()
        ).hexdigest()
        
        
        token = f"{timestamp}:{random_part}:{token_hash}"
        
        
        with self._lock:
            self._tokens[token] = {
                'user_id': user_id,
                'created_at': datetime.utcnow(),
                'session_id': session_id
            }
        
        return token
    
    def validate_token(self, token: str, user_id: int, session_id: str = None) -> bool:
        if not token:
            return False
        
        try:
            parts = token.split(':')
            if len(parts) != 3:
                return False
            
            timestamp_str, random_part, token_hash = parts
            
            
            with self._lock:
                if token not in self._tokens:
                    return False
                
                token_data = self._tokens[token]
                
                
                if datetime.utcnow() - token_data['created_at'] > self._token_ttl:
                    
                    del self._tokens[token]
                    return False
                
                
                if token_data['user_id'] != user_id:
                    return False
                
                
                if session_id and token_data.get('session_id') != session_id:
                    return False
            
            
            reconstructed_data = f"{user_id}:{timestamp_str}:{random_part}"
            if session_id:
                reconstructed_data += f":{session_id}"
            
            expected_hash = hashlib.sha256(
                f"{reconstructed_data}:{self.secret_key}".encode()
            ).hexdigest()
            
            
            return secrets.compare_digest(token_hash, expected_hash)
            
        except Exception:
            return False
    
    def invalidate_token(self, token: str) -> bool:
        with self._lock:
            if token in self._tokens:
                del self._tokens[token]
                return True
        return False
    
    def cleanup_expired(self) -> int:
        now = datetime.utcnow()
        removed = 0
        
        with self._lock:
            expired_tokens = [
                token for token, data in self._tokens.items()
                if now - data['created_at'] > self._token_ttl
            ]
            
            for token in expired_tokens:
                del self._tokens[token]
                removed += 1
        
        return removed



_csrf_manager: Optional[CSRFTokenManager] = None


def get_csrf_manager(secret_key: str = None) -> CSRFTokenManager:
    global _csrf_manager
    if _csrf_manager is None:
        _csrf_manager = CSRFTokenManager(secret_key)
    return _csrf_manager


def init_csrf_manager(secret_key: str) -> CSRFTokenManager:
    global _csrf_manager
    _csrf_manager = CSRFTokenManager(secret_key)
    return _csrf_manager
