import time
from collections import defaultdict
from threading import Lock
from typing import Dict, Tuple
from datetime import datetime, timedelta


class RateLimiter:
    
    def __init__(self):
        self._requests: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._lock = Lock()
        
        
        self.limits = {
            
            'login': (5, 60),           
            'register': (3, 300),       
            'password_reset': (3, 300), 
            'api_key': (10, 60),        
            'default': (100, 60),       
        }
    
    def _cleanup_old_requests(self, client_id: str, window: int):
        now = time.time()
        cutoff = now - window
        
        with self._lock:
            if client_id in self._requests:
                self._requests[client_id] = {
                    ts: count for ts, count in self._requests[client_id].items()
                    if ts > cutoff
                }
    
    def is_rate_limited(self, client_id: str, endpoint: str = 'default') -> Tuple[bool, int]:
        if endpoint not in self.limits:
            endpoint = 'default'
        
        max_requests, window = self.limits[endpoint]
        
        
        self._cleanup_old_requests(client_id, window)
        
        now = time.time()
        
        with self._lock:
            
            request_count = sum(
                count for ts, count in self._requests[client_id].items()
                if ts > now - window
            )
            
            if request_count >= max_requests:
                
                oldest_timestamp = min(self._requests[client_id].keys())
                retry_after = int(oldest_timestamp + window - now) + 1
                return True, max(1, retry_after)
            
            
            current_minute = int(now // 60) * 60  
            if current_minute not in self._requests[client_id]:
                self._requests[client_id][current_minute] = 0
            self._requests[client_id][current_minute] += 1
            
            return False, 0
    
    def get_retry_after_header(self, retry_after: int) -> str:
        return str(retry_after)
    
    def get_rate_limit_headers(self, endpoint: str = 'default') -> Dict[str, str]:
        if endpoint not in self.limits:
            endpoint = 'default'
        
        max_requests, window = self.limits[endpoint]
        
        return {
            'X-RateLimit-Limit': str(max_requests),
            'X-RateLimit-Window': str(window),
            'X-RateLimit-Remaining': str(max_requests),  
        }



rate_limiter = RateLimiter()


def get_rate_limiter() -> RateLimiter:
    return rate_limiter


def check_rate_limit(client_id: str, endpoint: str = 'default') -> Tuple[bool, int]:
    return rate_limiter.is_rate_limited(client_id, endpoint)
