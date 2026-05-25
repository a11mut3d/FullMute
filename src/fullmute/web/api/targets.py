from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Query
from typing import Optional, List
from io import TextIOWrapper

from fullmute.web.auth import get_current_user, require_role
from fullmute.web.database import (
    add_target_group, get_target_groups, add_target,
    add_targets_batch, get_targets, delete_target, get_db_connection
)
from fullmute.utils.logger import setup_logger

logger = setup_logger()

router = APIRouter()


@router.get("/groups")
async def get_all_groups(
    current_user: dict = Depends(get_current_user)
):
    
    if current_user['role'] == 'admin':
        return get_target_groups(organization_id=None)
    else:
        
        return get_target_groups(created_by=current_user['id'])


@router.post("/groups", dependencies=[Depends(require_role("scanner"))])
async def create_group(
    name: str = Form(...),
    description: str = Form(None),
    current_user: dict = Depends(get_current_user)
):
    group_id = add_target_group(
        name=name,
        description=description,
        user_id=current_user['id'],
        organization_id=current_user['organization_id']
    )
    return {"id": group_id, "name": name, "message": "Group created successfully"}


@router.delete("/groups/{group_id}", dependencies=[Depends(require_role("scanner"))])
async def delete_group(
    group_id: int,
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()

        
        if current_user['role'] == 'admin':
            cursor.execute("SELECT id, name FROM target_groups WHERE id = ?", (group_id,))
        else:
            cursor.execute("""
                SELECT id, name FROM target_groups
                WHERE id = ? AND created_by = ?
            """, (group_id, current_user['id']))

        group = cursor.fetchone()
        if not group:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Group not found or you don't have permission to delete it"
            )

        
        cursor.execute("""
            SELECT id FROM targets WHERE group_id = ?
        """, (group_id,))
        target_ids = [row['id'] for row in cursor.fetchall()]

        
        for target_id in target_ids:
            cursor.execute("DELETE FROM scan_targets WHERE target_id = ?", (target_id,))

        
        cursor.execute("DELETE FROM targets WHERE group_id = ?", (group_id,))
        deleted_targets = cursor.rowcount

        
        cursor.execute("DELETE FROM target_groups WHERE id = ?", (group_id,))

        conn.commit()

        return {
            "message": "Group deleted successfully",
            "group_name": group['name'],
            "deleted_targets": deleted_targets
        }


@router.get("")
async def get_all_targets(
    group_id: Optional[int] = Query(None),
    search: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    
    if current_user['role'] == 'admin':
        return get_targets(group_id=group_id, search=search, organization_id=None)
    else:
        
        return get_targets(group_id=group_id, search=search, created_by=current_user['id'])


@router.post("", dependencies=[Depends(require_role("scanner"))])
async def create_target(
    domain: str = Form(...),
    group_id: Optional[int] = Form(None),
    current_user: dict = Depends(get_current_user)
):
    from fullmute.utils.target_validator import validate_target, extract_host_and_port
    
    dangerous_patterns = ['${', '${', '<%', '%>', '__']
    for pattern in dangerous_patterns:
        if pattern in domain:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid domain: contains forbidden characters"
            )

    is_valid, host, error = validate_target(domain, require_ping=True)
    
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target: {error}"
        )
    
    
    _, port = extract_host_and_port(domain)
    
    
    domain_clean = host
    
    
    
    

    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, is_active FROM targets WHERE domain = ? AND created_by = ?", (domain_clean, current_user['id']))
        existing = cursor.fetchone()
        if existing:
            
            if not existing[1]:
                cursor.execute("UPDATE targets SET is_active = 1 WHERE id = ?", (existing[0],))
                conn.commit()
            return {"id": existing[0], "domain": domain_clean, "message": "Target already exists", "exists": True, "validated": True}

    
    
    

    logger.info(f"Adding target: domain={domain_clean}, user_id={current_user['id']}, group_id={group_id}")
    target_id = add_target(
        domain=domain_clean,
        group_id=group_id,
        created_by=current_user['id'],
        organization_id=current_user.get('organization_id', 1)
    )
    logger.info(f"Target add result: target_id={target_id}")

    if target_id:
        return {"id": target_id, "domain": domain_clean, "message": "Target added successfully", "exists": False, "validated": True}

    logger.error(f"Failed to add target: domain={domain_clean}")
    return {"id": 0, "domain": domain_clean, "message": "Failed to add target", "exists": False, "error": True}


@router.post("/bulk", dependencies=[Depends(require_role("scanner"))])
async def upload_targets(
    file: UploadFile = File(...),
    group_id: Optional[int] = Form(None),
    current_user: dict = Depends(get_current_user)
):
    """Upload targets from TXT file (one domain per line)"""
    import os
    import re
    import hashlib
    from datetime import datetime, timedelta

    
    
    
    logger.info(f"[BULK UPLOAD] Request started: user={current_user.get('username')}, file={file.filename if file else 'None'}")
    
    
    
    
    
    
    if not hasattr(upload_targets, '_rate_limit'):
        upload_targets._rate_limit = {}
    
    user_id = current_user['id']
    now = datetime.now()
    
    
    upload_targets._rate_limit = {
        uid: ts for uid, ts in upload_targets._rate_limit.items()
        if now - ts < timedelta(minutes=1)
    }
    
    
    if user_id in upload_targets._rate_limit:
        last_upload = upload_targets._rate_limit[user_id]
        if now - last_upload < timedelta(seconds=6):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded (max 10 uploads per minute)"
            )
    
    upload_targets._rate_limit[user_id] = now
    
    
    
    
    
    
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No filename provided"
        )
    
    
    safe_filename = os.path.basename(file.filename)
    
    
    if '\x00' in safe_filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename characters"
        )
    
    
    dangerous_patterns = [
        '..', '/', '\\',  
        '%2e%2e', '%2f', '%5c',  
        '%252e', '%255c',  
        '....//', '..\\',  
        ':', '*', '?', '"', '<', '>', '|',  
        '~', '`', '$',  
    ]
    
    filename_lower = safe_filename.lower()
    for pattern in dangerous_patterns:
        if pattern in filename_lower:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid filename: contains forbidden pattern"
            )
    
    
    if not safe_filename.lower().endswith('.txt'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only TXT files are allowed"
        )
    
    
    name_parts = safe_filename.lower().split('.')
    if len(name_parts) != 2 or name_parts[1] != 'txt':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file extension"
        )
    
    
    
    

    try:
        logger.info(f"[BULK UPLOAD] Reading file: {file.filename}, size={file.size if file.size else 'unknown'}")
        
        
        MAX_FILE_SIZE = 10 * 1024 * 1024  
        MAX_LINES = 12000  
        MAX_LINE_LENGTH = 253
        CHUNK_SIZE = 8192  

        contents = b''
        total_size = 0

        
        while True:
            chunk = await file.read(CHUNK_SIZE)
            if not chunk:
                break

            total_size += len(chunk)
            
            
            if total_size > MAX_FILE_SIZE:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="File too large (max 10MB)"
                )
            
            
            if len(chunk) > 100:
                unique_ratio = len(set(chunk)) / 256.0
                if unique_ratio < 0.01:  
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid file content: appears to be compressed/corrupted"
                    )
            
            contents += chunk
        
        
        if b'\x00' in contents:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file content: contains null bytes"
            )
        
        
        non_text_count = sum(1 for byte in contents if byte > 127 and byte not in (10, 13))
        if non_text_count > len(contents) * 0.1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file content: appears to be binary"
            )
        
        
        try:
            text_content = contents.decode('utf-8')
            logger.info(f"[BULK UPLOAD] File decoded: {len(text_content)} chars, {len(text_content.splitlines())} lines")
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file encoding (must be UTF-8)"
            )

        
        
        

        from fullmute.utils.target_validator import (
            validate_target, extract_host_and_port,
            is_blocked_hostname, validate_domain_format, validate_ip_format
        )

        domains = []
        blocked_hosts = ['localhost', '127.0.0.1', '::1', '0.0.0.0']


        injection_patterns = ['${', '<%', '%>', '__', '\\x00']

        line_count = 0
        valid_count = 0
        validation_errors = []

        logger.info(f"[BULK UPLOAD] Starting domain validation...")

        for line in text_content.splitlines():
            line_count += 1


            if line_count > MAX_LINES * 2:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Too many lines in file (max {MAX_LINES * 2})"
                )

            line = line.strip()
            if not line:
                continue

            
            
            
            
            
            has_injection = False
            for pattern in injection_patterns:
                if pattern in line:
                    has_injection = True
                    break
            
            if has_injection:
                validation_errors.append(f"Line {line_count}: contains forbidden pattern")
                continue

            
            
            
            
            
            if line.startswith('http://'):
                line = line[7:]
            elif line.startswith('https://'):
                line = line[8:]

            
            if '/' in line:
                line = line.split('/')[0]

            
            if len(line) > MAX_LINE_LENGTH:
                validation_errors.append(f"Line {line_count}: domain too long")
                continue

            
            host_only, _ = extract_host_and_port(line)

            
            host_lower = host_only.lower()
            if host_lower in blocked_hosts or is_blocked_hostname(host_lower):
                validation_errors.append(f"Line {line_count}: host is blocked")
                continue
            
            if host_lower.endswith('.local') or host_lower.endswith('.internal'):
                validation_errors.append(f"Line {line_count}: internal host not allowed")
                continue

            
            is_ip = validate_ip_format(host_only)
            is_domain = validate_domain_format(host_only)
            
            if not is_ip and not is_domain:
                validation_errors.append(f"Line {line_count}: invalid format")
                continue

            
            
            
            
            
            
            
            
            

            domains.append(line)
            valid_count += 1

            
            if valid_count > MAX_LINES:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Too many domains (max {MAX_LINES})"
                )

        if not domains:
            error_detail = "No valid domains found in file"
            if validation_errors:
                
                error_detail += f". Errors: {'; '.join(validation_errors[:5])}"
            logger.warning(f"[BULK UPLOAD] {error_detail}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_detail
            )
        else:
            logger.info(f"[BULK UPLOAD] Validated {len(domains)} domains out of {line_count} lines")

        
        logger.info(f"[BULK UPLOAD] Adding {len(domains)} targets to database...")
        added = add_targets_batch(
            domains=domains,
            group_id=group_id,
            created_by=current_user['id'],
            organization_id=current_user['organization_id']
        )
        logger.info(f"[BULK UPLOAD] Successfully added {added} targets")

        return {
            "added": added,
            "total": len(domains),
            "message": f"Added {added} targets successfully"
        }

    except HTTPException:
        raise
    except Exception as e:
        
        logger.error(f"[BULK UPLOAD] Unexpected error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process file"
        )


@router.delete("/{target_id}", dependencies=[Depends(require_role("scanner"))])
async def remove_target(
    target_id: int,
    current_user: dict = Depends(get_current_user)
):
    success = delete_target(target_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found"
        )

    return {"message": "Target deleted successfully"}


@router.put("/{target_id}/move", dependencies=[Depends(require_role("scanner"))])
async def move_target_to_group(
    target_id: int,
    group_id: Optional[str] = Form(None),
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        
        if current_user['role'] == 'admin':
            cursor.execute("SELECT id FROM targets WHERE id = ?", (target_id,))
        else:
            cursor.execute("SELECT id FROM targets WHERE id = ? AND created_by = ?", (target_id, current_user['id']))
        
        if not cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        
        group_id_val = int(group_id) if group_id else None
        cursor.execute("UPDATE targets SET group_id = ? WHERE id = ?", (group_id_val, target_id))
        conn.commit()
    
    return {"message": "Target moved successfully"}
