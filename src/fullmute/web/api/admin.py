"""
Admin API - Global settings for all users
"""
from fastapi import APIRouter, Depends, HTTPException, status, Form
from pydantic import BaseModel
from typing import Optional
import yaml
from pathlib import Path

from fullmute.web.auth import get_current_user, require_role
from fullmute.utils.logger import setup_logger

logger = setup_logger()
router = APIRouter()


CONFIG_PATH = Path(__file__).resolve().parents[3].parent / "config.yaml"


class GlobalSettings(BaseModel):
    max_concurrent_scans: int = 10


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        logger.warning(f"Config file not found: {CONFIG_PATH}")
        return {}
    
    try:
        with open(CONFIG_PATH, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return {}


def save_config(config: dict) -> bool:
    try:
        with open(CONFIG_PATH, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        logger.info(f"Config saved to {CONFIG_PATH}")
        return True
    except Exception as e:
        logger.error(f"Error saving config: {e}")
        return False


@router.get("")
async def get_global_settings(current_user: dict = Depends(require_role("admin"))):
    config = load_config()
    scanner_config = config.get('scanner', {})
    
    return {
        "max_concurrent_scans": scanner_config.get('max_concurrent', 10)
    }


@router.post("")
async def update_global_settings(
    max_concurrent_scans: int = Form(...),
    current_user: dict = Depends(require_role("admin"))
):
    
    if max_concurrent_scans < 1 or max_concurrent_scans > 20:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="max_concurrent_scans must be between 1 and 20"
        )
    
    
    config = load_config()
    if not config:
        config = {}
    
    
    if 'scanner' not in config:
        config['scanner'] = {}
    
    config['scanner']['max_concurrent'] = max_concurrent_scans
    
    
    if save_config(config):
        return {"message": "Global settings updated successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save global settings"
        )
