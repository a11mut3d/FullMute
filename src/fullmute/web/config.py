from pydantic_settings import BaseSettings
from typing import List
import os
import secrets


def generate_secret_key() -> str:
    return secrets.token_urlsafe(32)



_env_secret = os.getenv('FULLMUTE_SECRET_KEY')


if not _env_secret:
    _default_secret = generate_secret_key()
    
    if os.getenv('FULLMUTE_PRODUCTION', 'false').lower() == 'true':
        raise ValueError(
            "SECURITY ERROR: FULLMUTE_SECRET_KEY must be set in production! "
            "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
        )
else:
    _default_secret = _env_secret


class WebConfig(BaseSettings):
    
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False
    production: bool = False  

    
    database_path: str = "fullmute_web.db"
    scanner_database: str = "fullmute.db"

    
    
    secret_key: str = _default_secret
    token_expire_hours: int = 24
    allowed_origins: str = "http://localhost:8080"  

    
    max_concurrent_scans: int = 5
    scan_timeout: int = 300
    creds_max_attempts: int = 5  
    creds_timeout: int = 10  

    
    max_upload_size: int = 10 * 1024 * 1024  
    allowed_extensions: List[str] = ["txt"]

    class Config:
        env_prefix = "FULLMUTE_"
        env_file = ".env"
        extra = "ignore"


config = WebConfig()


if config.secret_key == _default_secret and not _env_secret:
    import warnings
    warnings.warn(
        "SECURITY WARNING: Using auto-generated SECRET_KEY. "
        "This key will change on each restart, invalidating all sessions. "
        "Set FULLMUTE_SECRET_KEY environment variable for stable deployments. "
        "Generate with: python -c 'import secrets; print(secrets.token_urlsafe(32))'",
        UserWarning
    )
