from fastapi import APIRouter, Depends, HTTPException, status, Form
from pydantic import BaseModel
from typing import Optional, List

from fullmute.web.auth import get_current_user
from fullmute.web.database import (
    get_user_settings, update_user_settings, get_or_create_user_settings
)

router = APIRouter()


class UserSettings(BaseModel):
    nvd_api_key: Optional[str] = ""
    proxy_enabled: bool = False
    proxy_list: Optional[str] = ""
    
    port_scan_enabled: bool = False
    port_scan_with_cves: bool = False
    port_scan_with_exploits: bool = False
    test_default_credentials: bool = False
    search_exploits: bool = False


@router.get("")
async def get_user_settings_endpoint(current_user: dict = Depends(get_current_user)):
    settings = get_or_create_user_settings(current_user['id'])

    
    return {
        "nvd_api_key_set": bool(settings.get('nvd_api_key')),
        "nvd_api_key_prefix": settings.get('nvd_api_key', '')[:8] + "..." if settings.get('nvd_api_key') else None,
        "proxy_enabled": settings.get('proxy_enabled', False),
        "proxy_list": settings.get('proxy_list', ''),
        
        "port_scan_enabled": settings.get('port_scan_enabled', False),
        "port_scan_with_cves": settings.get('port_scan_with_cves', False),
        "port_scan_with_exploits": settings.get('port_scan_with_exploits', False),
        "test_default_credentials": settings.get('test_default_credentials', False),
        "search_exploits": settings.get('search_exploits', False)
    }


@router.post("")
async def update_user_settings_endpoint(
    nvd_api_key: Optional[str] = Form(None),
    proxy_enabled: bool = Form(False),
    proxy_list: Optional[str] = Form(None),
    port_scan_enabled: bool = Form(False),
    port_scan_with_cves: bool = Form(False),
    port_scan_with_exploits: bool = Form(False),
    test_default_credentials: bool = Form(False),
    search_exploits: bool = Form(False),
    current_user: dict = Depends(get_current_user)
):
    
    if proxy_enabled and proxy_list:
        proxies = [p.strip() for p in proxy_list.split('\n') if p.strip()]
        for proxy in proxies:
            if not proxy.startswith(('http://', 'https://', 'socks5://', 'socks4://')):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid proxy format: {proxy}. Must start with http://, https://, socks5://, or socks4://"
                )

    success = update_user_settings(
        user_id=current_user['id'],
        nvd_api_key=nvd_api_key,
        proxy_enabled=proxy_enabled,
        proxy_list=proxy_list,
        port_scan_enabled=port_scan_enabled,
        port_scan_with_cves=port_scan_with_cves,
        port_scan_with_exploits=port_scan_with_exploits,
        test_default_credentials=test_default_credentials,
        search_exploits=search_exploits
    )

    if success:
        return {"message": "Settings updated successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update settings"
        )


@router.delete("/nvd-key")
async def clear_nvd_api_key(
    current_user: dict = Depends(get_current_user)
):
    success = update_user_settings(
        user_id=current_user['id'],
        nvd_api_key=""
    )

    if success:
        return {"message": "NVD API key cleared successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clear NVD API key"
        )
