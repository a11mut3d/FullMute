import asyncio
import gc
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import sqlite3
import json

from fullmute.web.database import (
    get_scan, get_scan_targets, get_targets,
    update_scan_status, get_scanner_db_path, get_db_connection,
    update_scan_results, get_scan_results, get_user_settings,
    close_thread_db_connection
)
from fullmute.core.scanner import FullMuteScanner
from fullmute.web.scan_queue import get_scan_queue_manager, ScanStatus
from fullmute.utils.logger import setup_logger

logger = setup_logger()


def get_port_scanner():
    from fullmute.scanner.port_scanner import PortScanner
    return PortScanner


active_scans: Dict[int, Dict[str, Any]] = {}
active_scans_lock = asyncio.Lock()


MAX_RESULTS_IN_MEMORY = 100  
MEMORY_CHECK_INTERVAL = 10  


def get_domain_findings(domain: str) -> Dict[str, Any]:
    scanner_db = get_scanner_db_path()
    try:
        conn = sqlite3.connect(scanner_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        
        cursor.execute("SELECT id FROM domains WHERE domain = ?", (domain,))
        domain_row = cursor.fetchone()
        if not domain_row:
            conn.close()
            return {'technologies': [], 'cves': [], 'sensitive_files': []}

        domain_id = domain_row['id']

        
        cursor.execute("SELECT * FROM technologies WHERE domain_id = ?", (domain_id,))
        technologies = [dict(row) for row in cursor.fetchall()]

        
        cursor.execute("""
            SELECT c.*, t.name as tech_name, t.version as tech_version
            FROM cves c
            JOIN technologies t ON c.technology_id = t.id
            WHERE t.domain_id = ?
        """, (domain_id,))
        cves = [dict(row) for row in cursor.fetchall()]

        
        cursor.execute("SELECT * FROM sensitive_files WHERE domain_id = ?", (domain_id,))
        sensitive_files = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return {
            'technologies': technologies,
            'cves': cves,
            'sensitive_files': sensitive_files
        }
    except Exception as e:
        logger.error(f"Error getting findings for {domain}: {e}")
        return {'technologies': [], 'cves': [], 'sensitive_files': []}


async def run_scan(scan_id: int, user_id: int, target_ids: List[int], test_default_credentials: bool = True, search_exploits: bool = False, port_scan_enabled: bool = False, port_scan_with_cves: bool = False, port_scan_with_exploits: bool = False):

    scanner = None
    port_scanner = None
    
    try:
        
        user_settings = get_user_settings(user_id) or {}
        nvd_api_key = user_settings.get('nvd_api_key', '')
        proxy_enabled = user_settings.get('proxy_enabled', False)
        proxy_list = user_settings.get('proxy_list', '')
        max_concurrent_scans = user_settings.get('max_concurrent_scans', 3)
        
        
        if port_scan_enabled is False:
            port_scan_enabled = user_settings.get('port_scan_enabled', False)
        if port_scan_with_cves is False:
            port_scan_with_cves = user_settings.get('port_scan_with_cves', False)
        if port_scan_with_exploits is False:
            port_scan_with_exploits = user_settings.get('port_scan_with_exploits', False)

        logger.info(f"Scan {scan_id}: Starting with user {user_id} settings (NVD: {'yes' if nvd_api_key else 'no'}, Proxy: {'on' if proxy_enabled else 'off'}, Test Creds: {test_default_credentials}, Port Scan: {port_scan_enabled})")

        
        async with active_scans_lock:
            active_scans[scan_id] = {
                'status': 'running',
                'progress': 0,
                'total': len(target_ids),
                'completed': 0,
                'current_target': '',
                'findings': {
                    'technologies': 0,
                    'cves': 0,
                    'sensitive_files': 0,
                    'cameras': 0,
                    'default_credentials': 0,
                    'open_ports': 0
                },
                'started_at': datetime.now().isoformat(),
                'results': [],
                'user_id': user_id
            }

        
        update_scan_status(scan_id, 'running', progress=0)

        
        scan_targets = get_scan_targets(scan_id)
        domains = [t['domain'] for t in scan_targets]

        if not domains:
            update_scan_status(scan_id, 'completed', progress=100)
            async with active_scans_lock:
                if scan_id in active_scans:
                    active_scans[scan_id]['status'] = 'completed'
            
            queue_manager = get_scan_queue_manager()
            await queue_manager.complete_scan(scan_id, user_id, ScanStatus.COMPLETED)
            return

        
        proxies = []
        if proxy_enabled and proxy_list:
            proxies = [p.strip() for p in proxy_list.split('\n') if p.strip()]

        
        scanner_db = get_scanner_db_path()

        
        from fullmute.db.engine import init_db
        try:
            init_db(scanner_db)
            logger.info(f"Scanner database initialized at {scanner_db}")
        except Exception as e:
            logger.error(f"Failed to initialize scanner database: {e}")

        scanner_config = {
            'max_concurrent': max_concurrent_scans,  
            'timeout': 15,
            'proxy_enabled': proxy_enabled and len(proxies) > 0,
            'proxy_file': None,  
            'proxies': proxies,  
            'min_delay': 0.5,
            'max_delay': 1.5,
            'nvd_api_key': nvd_api_key if nvd_api_key else None,
            'test_default_credentials': test_default_credentials,  
            'max_scans_before_cleanup': 20  
        }

        scanner = FullMuteScanner(
            db_path=scanner_db,
            config=scanner_config
        )

        total = len(domains)
        completed = 0
        start_time = time.time()

        
        semaphore = asyncio.Semaphore(max_concurrent_scans)
        consecutive_failures = 0
        max_consecutive_failures = max_concurrent_scans * 3

        async def scan_domain_wrapper(domain):
            nonlocal completed, consecutive_failures
            
            async with semaphore:
                try:
                    
                    scan_data = get_scan(scan_id)
                    if scan_data and scan_data.get('status') == 'cancelled':
                        logger.info(f"Scan {scan_id} was cancelled, stopping...")
                        return None

                    async with active_scans_lock:
                        active_scans[scan_id]['current_target'] = domain

                    
                    result = await asyncio.wait_for(
                        scanner.scan_domain(domain),
                        timeout=30.0  
                    )
                    
                    
                    consecutive_failures = 0
                    
                    completed += 1
                    progress = int((completed / total) * 100)

                    
                    update_scan_status(scan_id, 'running', progress=progress)

                    async with active_scans_lock:
                        active_scans[scan_id]['progress'] = progress
                        active_scans[scan_id]['completed'] = completed
                        active_scans[scan_id]['current_target'] = domain

                    
                    techs = result.get('technologies', {}) or {}
                    cves = result.get('cves', {}) or {}
                    files = result.get('sensitive_files', []) or []
                    cameras = result.get('cameras', []) or []
                    default_creds = result.get('default_credentials', []) or []

                    
                    tech_list = []
                    if isinstance(techs, dict):
                        for tech_type, tech_items in techs.items():
                            if isinstance(tech_items, list):
                                for tech in tech_items:
                                    tech_list.append({'name': tech, 'category': tech_type, 'version': ''})
                            elif isinstance(tech_items, dict):
                                for tech_name, tech_version in tech_items.items():
                                    tech_list.append({'name': tech_name, 'category': tech_type, 'version': tech_version})
                    elif isinstance(techs, list):
                        tech_list = [{'name': t, 'category': 'unknown', 'version': ''} for t in techs]

                    
                    cve_list = []
                    if isinstance(cves, dict):
                        for tech_name, cve_items in cves.items():
                            if isinstance(cve_items, list):
                                for cve in cve_items:
                                    if isinstance(cve, dict):
                                        cve_list.append({
                                            'cve_id': cve.get('id', ''),
                                            'severity': cve.get('cvss', {}).get('severity', ''),
                                            'cvss_score': cve.get('cvss', {}).get('score', ''),
                                            'description': cve.get('description', ''),
                                            'tech_name': tech_name.split(' (')[0] if ' (' in tech_name else tech_name,
                                            'tech_version': ''
                                        })
                    elif isinstance(cves, list):
                        cve_list = cves

                    tech_count = len(tech_list)
                    cve_count = len(cve_list)

                    
                    exploit_results = {}
                    if search_exploits and cve_list:
                        from fullmute.utils.searchsploit import search_sploit_batch
                        cve_ids = [cve['cve_id'] for cve in cve_list if cve.get('cve_id')]
                        if cve_ids:
                            logger.info(f"Searching exploits for {len(cve_ids)} CVEs...")
                            exploit_results = search_sploit_batch(cve_ids)
                            total_exploits = sum(len(exps) for exps in exploit_results.values())
                            if total_exploits > 0:
                                logger.info(f"Found {total_exploits} exploits for {domain}")

                    
                    port_scan_results = []
                    if port_scan_enabled:
                        try:
                            PortScanner = get_port_scanner()
                            port_scanner_instance = PortScanner(timeout=5.0, max_concurrent=10)

                            logger.info(f"Port scanning {domain}...")
                            port_results = await port_scanner_instance.scan_with_cves(
                                domain,
                                nvd_api_key=nvd_api_key if port_scan_with_cves else None,
                                search_exploits=port_scan_with_exploits,
                                test_default_credentials=test_default_credentials,
                                resolve_domain=True
                            )

                            port_scan_results = []
                            for r in port_results:
                                logger.debug(f"Port {r.port}: state={r.state}, service={r.service}")

                                if r.state == 'open':
                                    port_scan_results.append({
                                        'port': r.port,
                                        'service': r.service if r.service else 'unknown',
                                        'version': r.version if r.version and r.version != 'undefined' else '',
                                        'banner': r.banner if r.banner and r.banner != 'undefined' else '',
                                        'ssl': r.ssl or False,
                                        'product': r.product if r.product and r.product != 'undefined' else '',
                                        'protocol': r.protocol if r.protocol else 'tcp',
                                        'cves': r.cves if port_scan_with_cves and r.cves else [],
                                        'exploits': r.exploits if port_scan_with_exploits and r.exploits else []
                                    })

                            logger.info(f"Port scan found {len(port_scan_results)} open ports on {domain}")

                        except Exception as e:
                            error_msg = str(e)
                            if 'SSH' in error_msg or 'paramiko' in error_msg.lower():
                                logger.warning(f"SSH error during port scan for {domain}: {error_msg} (ignored)")
                            else:
                                logger.error(f"Port scan error for {domain}: {e}")
                            port_scan_results = []

                    
                    async with active_scans_lock:
                        active_scans[scan_id]['findings']['technologies'] += tech_count
                        active_scans[scan_id]['findings']['cves'] += cve_count
                        active_scans[scan_id]['findings']['sensitive_files'] += len(files)
                        active_scans[scan_id]['findings']['cameras'] += len(cameras)
                        active_scans[scan_id]['findings']['default_credentials'] += len(default_creds)
                        active_scans[scan_id]['findings']['open_ports'] += len(port_scan_results) if port_scan_results else 0

                        result_data = {
                            'domain': domain,
                            'technologies_count': tech_count,
                            'cves_count': cve_count,
                            'sensitive_files_count': len(files),
                            'cameras_count': len(cameras),
                            'default_credentials_count': len(default_creds),
                            'exploits_count': sum(len(exps) for exps in exploit_results.values()) if exploit_results else 0,
                            'port_scan_count': len(port_scan_results) if port_scan_results else 0,
                            'status': 'completed' if not result.get('error') else 'failed',
                            'technologies': tech_list,
                            'cves': cve_list,
                            'sensitive_files': files,
                            'default_credentials': default_creds,
                            'exploits': exploit_results,
                            'open_ports': port_scan_results
                        }

                        if len(active_scans[scan_id]['results']) >= MAX_RESULTS_IN_MEMORY:
                            active_scans[scan_id]['results'].pop(0)

                        active_scans[scan_id]['results'].append(result_data)

                    logger.info(f"Scan {scan_id}: Scanned {domain} - Progress: {progress}% ({completed}/{total})")
                    
                    return result_data

                except asyncio.TimeoutError:
                    consecutive_failures += 1
                    completed += 1
                    logger.warning(f"Scan {scan_id}: Timeout scanning {domain} (failures: {consecutive_failures})")
                    
                    if consecutive_failures >= max_consecutive_failures:
                        logger.error(f"Too many consecutive failures ({consecutive_failures}), stopping scan")
                    
                    return None
                    
                except Exception as e:
                    consecutive_failures += 1
                    completed += 1
                    logger.error(f"Scan {scan_id}: Error scanning {domain}: {e}")
                    
                    if consecutive_failures >= max_consecutive_failures:
                        logger.error(f"Too many consecutive failures ({consecutive_failures}), stopping scan")
                    
                    return None

        
        tasks = [scan_domain_wrapper(domain) for domain in domains]
        
        
        for i in range(0, len(tasks), max_concurrent_scans * 2):
            batch = tasks[i:i + max_concurrent_scans * 2]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error(f"Task failed with exception: {result}")
                elif result is not None:
                    pass  
            
            
            if (i + len(batch)) % MEMORY_CHECK_INTERVAL == 0:
                elapsed = time.time() - start_time
                logger.info(f"Scan {scan_id}: Progress check - {completed}/{total} domains, {elapsed:.1f}s elapsed")
                gc.collect()

        
        scan_data = get_scan(scan_id)
        logger.info(f"Scan {scan_id}: Determining final status. Database status: {scan_data.get('status') if scan_data else 'None'}")

        async with active_scans_lock:
            if scan_data and scan_data.get('status') == 'cancelled':
                final_status = ScanStatus.CANCELLED
                active_scans[scan_id]['status'] = 'cancelled'
            else:
                final_status = ScanStatus.COMPLETED
                active_scans[scan_id]['status'] = 'completed'
                update_scan_status(scan_id, 'completed', progress=100)

            active_scans[scan_id]['completed_at'] = datetime.now().isoformat()
            
            
            results = list(active_scans[scan_id].get('results', []))

        logger.info(f"Scan {scan_id}: Final status={final_status}, results count={len(results)}")

        
        update_scan_results(scan_id, results)
        logger.info(f"Results saved for scan {scan_id}")

        
        queue_manager = get_scan_queue_manager()
        queue_manager.complete_scan(scan_id, user_id, final_status)

        logger.info(f"Scan {scan_id} completed successfully in {time.time() - start_time:.1f}s")

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        update_scan_status(scan_id, 'failed')
        async with active_scans_lock:
            if scan_id in active_scans:
                active_scans[scan_id]['status'] = 'failed'

        
        queue_manager = get_scan_queue_manager()
        queue_manager.complete_scan(scan_id, user_id, ScanStatus.FAILED)
    finally:
        
        try:
            if scanner:
                await scanner.close()
            
            close_thread_db_connection()
            
            gc.collect()
            logger.debug(f"Scan {scan_id}: Resources cleaned up")
        except Exception as e:
            logger.debug(f"Error during cleanup: {e}")


def run_scan_sync(scan_id: int, user_id: int, target_ids: List[int], test_default_credentials: bool = True, search_exploits: bool = False, port_scan_enabled: bool = False, port_scan_with_cves: bool = False, port_scan_with_exploits: bool = False):
    try:
        asyncio.run(run_scan(
            scan_id, 
            user_id, 
            target_ids, 
            test_default_credentials, 
            search_exploits,
            port_scan_enabled,
            port_scan_with_cves,
            port_scan_with_exploits
        ))
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        if scan_id in active_scans:
            active_scans[scan_id]['status'] = 'failed'


def get_scan_progress(scan_id: int) -> Dict[str, Any]:
    return active_scans.get(scan_id, {})


def cleanup_completed_scan(scan_id: int):
    if scan_id in active_scans:
        del active_scans[scan_id]
