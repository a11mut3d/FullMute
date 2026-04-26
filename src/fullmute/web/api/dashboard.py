"""
Dashboard API endpoints
"""
from fastapi import APIRouter, Depends
import sqlite3
from pathlib import Path

from fullmute.web.auth import get_current_user
from fullmute.web.database import get_dashboard_stats, get_scans, get_db_connection, get_scanner_db_path
from fullmute.web.config import config

router = APIRouter()


@router.get("/stats")
async def get_statistics(
    current_user: dict = Depends(get_current_user)
):
    org_id = current_user.get('organization_id', 1)

    
    if current_user['role'] == 'admin':
        stats = get_dashboard_stats(organization_id=None)  
    else:
        stats = get_dashboard_stats(user_id=current_user['id'])  

    
    
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if current_user['role'] == 'admin':
            cursor.execute("SELECT id FROM scans WHERE status IN ('completed', 'failed', 'cancelled')")
            completed_scan_ids = [row[0] for row in cursor.fetchall()]
        else:
            
            cursor.execute("SELECT id FROM scans WHERE created_by = ? AND status IN ('completed', 'failed', 'cancelled')", (current_user['id'],))
            completed_scan_ids = [row[0] for row in cursor.fetchall()]

    
    if not completed_scan_ids:
        stats['cms_count'] = 0
        stats['total_cves'] = 0
        stats['cves_critical'] = 0
        stats['cves_high'] = 0
        stats['cves_medium'] = 0
        stats['cves_low'] = 0
        stats['total_technologies'] = 0
        stats['total_sensitive_files'] = 0
        return stats
    
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT t.domain 
            FROM scan_targets st
            JOIN targets t ON st.target_id = t.id
            WHERE st.scan_id IN ({})
        """.format(','.join('?' * len(completed_scan_ids))), completed_scan_ids)
        scanned_domains = [row[0] for row in cursor.fetchall()]
    
    
    scanner_db = get_scanner_db_path()
    try:
        conn = sqlite3.connect(scanner_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='domains'")
        if not cursor.fetchone():
            
            stats['cms_count'] = 0
            stats['total_cves'] = 0
            stats['cves_critical'] = 0
            stats['cves_high'] = 0
            stats['cves_medium'] = 0
            stats['cves_low'] = 0
            stats['total_technologies'] = 0
            stats['total_sensitive_files'] = 0
            conn.close()
            return stats
        
        
        if not scanned_domains:
            stats['cms_count'] = 0
            stats['total_cves'] = 0
            stats['cves_critical'] = 0
            stats['cves_high'] = 0
            stats['cves_medium'] = 0
            stats['cves_low'] = 0
            stats['total_technologies'] = 0
            stats['total_sensitive_files'] = 0
            conn.close()
            return stats

        
        placeholders = ','.join('?' * len(scanned_domains))
        cursor.execute(f"SELECT id FROM domains WHERE domain IN ({placeholders})", scanned_domains)
        domain_ids = [row['id'] for row in cursor.fetchall()]

        if not domain_ids:
            
            stats['cms_count'] = 0
            stats['total_cves'] = 0
            stats['cves_critical'] = 0
            stats['cves_high'] = 0
            stats['cves_medium'] = 0
            stats['cves_low'] = 0
            stats['total_technologies'] = 0
            stats['total_sensitive_files'] = 0
            conn.close()
            return stats

        
        domain_ids_tuple = tuple(domain_ids)
        
        
        cursor.execute(f"""
            SELECT c.severity, COUNT(*) as count
            FROM cves c
            JOIN technologies t ON c.technology_id = t.id
            WHERE t.domain_id IN ({placeholders})
            GROUP BY c.severity
        """, domain_ids)
        cves_by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}

        
        cursor.execute(f"""
            SELECT category, COUNT(*) as count
            FROM technologies
            WHERE domain_id IN ({placeholders})
            GROUP BY category
        """, domain_ids)
        techs_by_category = {row['category']: row['count'] for row in cursor.fetchall()}

        
        cursor.execute(f"""
            SELECT COUNT(*) as count FROM technologies
            WHERE category = 'cms' AND domain_id IN ({placeholders})
        """, domain_ids)
        stats['cms_count'] = cursor.fetchone()['count']
        
        
        cursor.execute("""
            SELECT COUNT(*) as count FROM cves c
            JOIN technologies t ON c.technology_id = t.id
            WHERE t.domain_id IN ({})
        """.format(','.join('?' * len(domain_ids))), domain_ids)
        stats['total_cves'] = cursor.fetchone()['count']
        
        
        stats['cves_critical'] = cves_by_severity.get('CRITICAL', 0)
        stats['cves_high'] = cves_by_severity.get('HIGH', 0)
        stats['cves_medium'] = cves_by_severity.get('MEDIUM', 0)
        stats['cves_low'] = cves_by_severity.get('LOW', 0)
        
        
        stats['total_technologies'] = sum(techs_by_category.values())
        
        
        cursor.execute("""
            SELECT COUNT(*) as count FROM sensitive_files 
            WHERE domain_id IN ({})
        """.format(','.join('?' * len(domain_ids))), domain_ids)
        stats['total_sensitive_files'] = cursor.fetchone()['count']
        
        conn.close()
    except Exception as e:
        print(f"Dashboard stats error: {e}")
        
        stats['cms_count'] = 0
        stats['total_cves'] = 0
        stats['cves_critical'] = 0
        stats['cves_high'] = 0
        stats['cves_medium'] = 0
        stats['cves_low'] = 0
        stats['total_technologies'] = 0
        stats['total_sensitive_files'] = 0
    
    return stats
