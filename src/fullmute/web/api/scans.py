from fastapi import APIRouter, Depends, HTTPException, status, Form, BackgroundTasks
from fastapi import Request
from typing import Optional, List
from datetime import datetime
import json
import threading
import sqlite3

from fullmute.web.auth import get_current_user, require_role
from fullmute.web.database import (
    create_scan_config, get_scan_configs, create_scan,
    get_scans, get_scan, get_scan_targets, get_targets,
    update_scan_status, get_db_connection, get_scan_results, get_scanner_db_path
)
from fullmute.web.scheduler import scheduler
from fullmute.web.scanner import run_scan_sync, get_scan_progress
from fullmute.web.scan_queue import get_scan_queue_manager
from fullmute.db.queries import DBQueries
from fullmute.utils.logger import setup_logger

logger = setup_logger()

router = APIRouter()


@router.get("/configs")
async def get_scan_configurations(
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        if current_user['role'] == 'admin':
            cursor.execute("""
                SELECT c.*, u.username as creator_name
                FROM scan_configs c
                LEFT JOIN users u ON c.created_by = u.id
                ORDER BY c.created_at DESC
            """)
        else:
            cursor.execute("""
                SELECT c.*, u.username as creator_name
                FROM scan_configs c
                LEFT JOIN users u ON c.created_by = u.id
                WHERE c.organization_id = ?
                ORDER BY c.created_at DESC
            """, (current_user['organization_id'],))
        
        configs = []
        for row in cursor.fetchall():
            config_dict = dict(row)
            config_dict['target_group_ids'] = json.loads(config_dict['target_group_ids'] or '[]')
            configs.append(config_dict)
        
        return configs


@router.post("/configs", dependencies=[Depends(require_role("admin"))])
async def create_scan_configuration(
    name: str = Form(...),
    description: str = Form(None),
    scan_type: str = Form("manual"),
    schedule_type: Optional[str] = Form(None),
    schedule_value: Optional[str] = Form(None),
    target_group_ids: str = Form("[]"),
    current_user: dict = Depends(get_current_user)
):
    import json
    
    try:
        group_ids = json.loads(target_group_ids) if target_group_ids else []
    except:
        group_ids = []
    
    config_id = create_scan_config(
        name=name,
        description=description or "",
        scan_type=scan_type,
        schedule_type=schedule_type,
        schedule_value=schedule_value,
        target_group_ids=group_ids,
        user_id=current_user['id']
    )
    
    
    if schedule_type and schedule_value:
        scheduler.add_scheduled_scan(
            config_id=config_id,
            schedule_type=schedule_type,
            schedule_value=schedule_value
        )
    
    return {
        "id": config_id,
        "name": name,
        "message": "Scan configuration created successfully"
    }


@router.post("/start", dependencies=[Depends(require_role("scanner"))])
async def start_scan(
    config_id: Optional[int] = Form(None),
    target_ids: str = Form(...),
    test_network: bool = Form(False),
    test_default_credentials: bool = Form(False),
    search_exploits: bool = Form(False),
    current_user: dict = Depends(get_current_user)
):
    
    target_id_list = []
    try:
        target_id_list = json.loads(target_ids) if target_ids else []

        
        if not isinstance(target_id_list, list):
            raise ValueError("target_ids must be a list")

        
        converted_ids = []
        for tid in target_id_list:
            try:
                
                converted_ids.append(int(tid))
            except (ValueError, TypeError):
                raise ValueError(f"Invalid target ID: {tid} (must be integer)")
        
        target_id_list = converted_ids

    except json.JSONDecodeError as e:
        logger.warning(f"Invalid JSON in target_ids: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid target_ids format"
        )
    except ValueError as e:
        logger.warning(f"Validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Unexpected error parsing target_ids: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to parse target_ids"
        )

    if not target_id_list:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No targets selected"
        )

    
    MAX_TARGETS_PER_SCAN = 1000
    if len(target_id_list) > MAX_TARGETS_PER_SCAN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Too many targets (max {MAX_TARGETS_PER_SCAN})"
        )

    
    try:
        from fullmute.web.database import create_scan
        scan_id = create_scan(
            config_id=config_id,
            target_ids=target_id_list,
            user_id=current_user['id'],
            organization_id=current_user['organization_id']
        )
    except Exception as e:
        logger.error(f"Error creating scan: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create scan"
        )

    
    user_scan_number = 1
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_scan_number FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            if row:
                user_scan_number = row[0]
    except:
        pass

    
    try:
        queue_manager = get_scan_queue_manager()
        queue_manager.add_scan(
            scan_id,
            current_user['id'],
            target_id_list,
            test_default_credentials,
            search_exploits,
            port_scan_enabled=test_network,
            port_scan_with_cves=test_network,  
            port_scan_with_exploits=search_exploits  
        )

        
        queue_status = queue_manager.get_user_queue_status(current_user['id'])
    except Exception as e:
        logger.error(f"Error adding scan to queue: {e}")
        
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scan_targets WHERE scan_id = ?", (scan_id,))
                cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
                conn.commit()
        except Exception:
            pass
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add scan to queue"
        )

    return {
        "id": scan_id,
        "user_scan_number": user_scan_number,
        "message": "Scan added to queue",
        "queue_position": queue_status.get('queued', 0),
        "running_scans": queue_status.get('running', 0),
        "max_concurrent": queue_status.get('max_concurrent', 3),
        "test_default_credentials": test_default_credentials
    }


@router.get("")
async def get_all_scans(
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()

        if current_user['role'] == 'admin':
            
            cursor.execute("""
                SELECT s.*, c.name as config_name, u.username as creator_name
                FROM scans s
                LEFT JOIN scan_configs c ON s.config_id = c.id
                LEFT JOIN users u ON s.created_by = u.id
                ORDER BY s.created_at DESC
                LIMIT ?
            """, (limit,))
        else:
            
            cursor.execute("""
                SELECT s.*, c.name as config_name, u.username as creator_name
                FROM scans s
                LEFT JOIN scan_configs c ON s.config_id = c.id
                LEFT JOIN users u ON s.created_by = u.id
                WHERE s.created_by = ?
                ORDER BY s.created_at DESC
                LIMIT ?
            """, (current_user['id'], limit))

        scans = []
        for row in cursor.fetchall():
            scan_dict = dict(row)
            
            cursor.execute("""
                SELECT t.domain
                FROM scan_targets st
                JOIN targets t ON st.target_id = t.id
                WHERE st.scan_id = ?
                LIMIT 5
            """, (scan_dict['id'],))
            targets = [dict(row) for row in cursor.fetchall()]
            scan_dict['targets'] = targets

            
            cursor.execute("""
                SELECT result_path FROM scan_targets WHERE scan_id = ?
            """, (scan_dict['id'],))
            result_paths = cursor.fetchall()

            
            cve_count = 0
            files_count = 0
            tech_count = 0
            camera_count = 0
            for rp in result_paths:
                if rp[0]:
                    try:
                        result_data = json.loads(rp[0])
                        cve_count += len(result_data.get('cves', []))
                        files_count += len(result_data.get('sensitive_files', []))
                        tech_count += len(result_data.get('technologies', []))
                    except:
                        pass

            
            scan_dict['progress_data'] = {
                'status': scan_dict.get('status', 'pending'),
                'progress': scan_dict.get('progress', 0),
                'current_target': '',
                'findings': {
                    'cves': cve_count,
                    'sensitive_files': files_count,
                    'technologies': tech_count,
                    'cameras': camera_count,
                    'open_ports': 0  
                }
            }

            
            scan_dict['findings'] = scan_dict['progress_data']['findings']

            scans.append(scan_dict)

        return scans


@router.get("/{scan_id}")
async def get_scan_details(
    scan_id: int,
    current_user: dict = Depends(get_current_user)
):
    
    scan = get_scan(
        scan_id=scan_id,
        user_id=current_user['id'],
        role=current_user['role'],
        organization_id=current_user.get('organization_id')
    )

    if not scan:
        
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    
    progress = get_scan_progress(scan_id)

    if progress and progress.get('status') == 'running':
        
        scan['progress_data'] = progress
    else:
        
        db_results = get_scan_results(scan_id)

        logger.info(f"API: Loaded {len(db_results)} results for scan {scan_id}")
        for r in db_results:
            logger.info(f"  - {r.get('domain')}: {len(r.get('technologies', []))} techs, {len(r.get('cves', []))} cves, {len(r.get('sensitive_files', []))} files, {len(r.get('default_credentials', []))} creds, {len(r.get('open_ports', []))} ports")

        
        for r in db_results:
            logger.info(f"Processing result for {r.get('domain')}:")

            
            if r.get('technologies'):
                logger.info(f"  Tech: {r['technologies'][:2]}")  
            else:
                logger.info(f"  Tech: EMPTY")

            
            if r.get('cves'):
                logger.info(f"  CVEs: {len(r['cves'])} items")
                for cve in r.get('cves', []):
                    if 'id' not in cve and 'cve_id' in cve:
                        cve['id'] = cve['cve_id']
            else:
                logger.info(f"  CVEs: EMPTY")

            
            if r.get('sensitive_files'):
                logger.info(f"  Files: {r['sensitive_files'][:2]}")  
                for file in r.get('sensitive_files', []):
                    if 'file_path' not in file and 'url' in file:
                        file['file_path'] = file['url']
                    if 'file_type' not in file:
                        file['file_type'] = file.get('file_type', 'unknown')
                    if 'verification_result' not in file:
                        file['verification_result'] = file.get('verification_result', 'unknown')
            else:
                logger.info(f"  Files: EMPTY")

            
            if r.get('default_credentials'):
                logger.info(f"  Creds: {r['default_credentials'][:2]}")  
            else:
                logger.info(f"  Creds: EMPTY, trying to load from Scanner DB...")
                domain = r.get('domain', '')
                if domain:
                    
                    scanner_db_path = get_scanner_db_path()
                    db = DBQueries(scanner_db_path)
                    creds = db.get_default_credentials_for_domain(domain)
                    if creds:
                        r['default_credentials'] = creds
                        logger.info(f"  Creds loaded from Scanner DB: {len(creds)} items")
                    else:
                        logger.info(f"  Creds: NOT FOUND in Scanner DB")

        
        tech_count = sum(len(r.get('technologies', [])) for r in db_results)
        cve_count = sum(len(r.get('cves', [])) for r in db_results)
        files_count = sum(len(r.get('sensitive_files', [])) for r in db_results)
        creds_count = sum(len(r.get('default_credentials', [])) for r in db_results)
        ports_count = sum(len(r.get('open_ports', [])) for r in db_results)  

        scan['progress_data'] = {
            'status': scan['status'],
            'progress': scan['progress'],
            'completed': scan['completed_targets'],
            'total': scan['total_targets'],
            'results': db_results,
            'findings': {
                'technologies': tech_count,
                'cves': cve_count,
                'sensitive_files': files_count,
                'default_credentials': creds_count,
                'cameras': 0,
                'open_ports': ports_count  
            }
        }

        logger.info(f"Returning scan data: {len(scan['progress_data']['results'])} results")

    scan['targets'] = get_scan_targets(scan_id)
    return scan


@router.get("/{scan_id}/progress")
async def get_scan_progress_endpoint(
    scan_id: int,
    current_user: dict = Depends(get_current_user)
):
    progress = get_scan_progress(scan_id)
    if not progress:
        
        scan = get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {
            "status": scan['status'],
            "progress": scan['progress'],
            "completed": scan['completed_targets'],
            "total": scan['total_targets']
        }
    return progress


@router.delete("/{scan_id}", dependencies=[Depends(require_role("scanner"))])
async def delete_scan(
    scan_id: int,
    current_user: dict = Depends(get_current_user)
):
    scan = get_scan(
        scan_id=scan_id,
        user_id=current_user['id'],
        role=current_user['role'],
        organization_id=current_user.get('organization_id')
    )

    if not scan:
        
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    if scan['status'] == 'running':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete a running scan. Cancel it first."
        )

    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_targets WHERE scan_id = ?", (scan_id,))
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()

    return {"message": "Scan deleted successfully"}


@router.get("/queue/status")
async def get_queue_status(
    current_user: dict = Depends(get_current_user)
):
    queue_manager = get_scan_queue_manager()
    status = queue_manager.get_user_queue_status(current_user['id'])
    return status


@router.post("/queue/start-next")
async def start_next_scan(
    current_user: dict = Depends(get_current_user)
):
    queue_manager = get_scan_queue_manager()
    user_queue = queue_manager.get_user_queue(current_user['id'])
    await user_queue._try_start_scans()
    return {"message": "Queue processed"}


@router.post("/{scan_id}/cancel", dependencies=[Depends(require_role("scanner"))])
async def cancel_scan(
    scan_id: int,
    current_user: dict = Depends(get_current_user)
):
    
    scan = get_scan(
        scan_id=scan_id,
        user_id=current_user['id'],
        role=current_user['role'],
        organization_id=current_user.get('organization_id')
    )

    if not scan:
        
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    
    queue_manager = get_scan_queue_manager()
    cancelled = queue_manager.cancel_scan(scan_id, current_user['id'])

    if cancelled:
        return {"message": "Scan cancelled successfully"}
    else:
        
        if scan['status'] in ['running', 'pending', 'queued']:
            update_scan_status(scan_id, 'cancelled')
            return {"message": "Scan cancelled successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Scan cannot be cancelled"
            )
