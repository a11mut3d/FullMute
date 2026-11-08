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

_SQLITE_BATCH_SIZE = 400


def _chunks(items, size=_SQLITE_BATCH_SIZE):
    for offset in range(0, len(items), size):
        yield items[offset:offset + size]


def _reset_finding_stats(stats):
    stats.update({
        'cms_count': 0,
        'total_cves': 0,
        'cves_critical': 0,
        'cves_high': 0,
        'cves_medium': 0,
        'cves_low': 0,
        'total_technologies': 0,
        'total_sensitive_files': 0,
    })
    return stats


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
            cursor.execute(
                "SELECT id FROM scans WHERE status IN ('completed', 'failed', 'cancelled')"
            )
        else:
            cursor.execute(
                """
                SELECT id FROM scans
                WHERE created_by = ? AND status IN ('completed', 'failed', 'cancelled')
                """,
                (current_user['id'],),
            )
        completed_scan_ids = [row[0] for row in cursor.fetchall()]

    
    if not completed_scan_ids:
        return _reset_finding_stats(stats)
    
    scanned_domains = set()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        for scan_id_batch in _chunks(completed_scan_ids):
            placeholders = ','.join('?' for _ in scan_id_batch)
            cursor.execute(
                f"""
                SELECT DISTINCT t.domain
                FROM scan_targets st
                JOIN targets t ON st.target_id = t.id
                WHERE st.scan_id IN ({placeholders})
                """,
                scan_id_batch,
            )
            scanned_domains.update(row[0] for row in cursor.fetchall())
    
    scanner_db = get_scanner_db_path()
    conn = None
    try:
        conn = sqlite3.connect(scanner_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='domains'")
        if not cursor.fetchone():
            return _reset_finding_stats(stats)
        
        
        if not scanned_domains:
            return _reset_finding_stats(stats)

        domain_ids = set()
        scanned_domain_list = list(scanned_domains)
        for domain_batch in _chunks(scanned_domain_list):
            placeholders = ','.join('?' for _ in domain_batch)
            cursor.execute(
                f"SELECT id FROM domains WHERE domain IN ({placeholders})",
                domain_batch,
            )
            domain_ids.update(row['id'] for row in cursor.fetchall())

        if not domain_ids:
            return _reset_finding_stats(stats)

        cves_by_severity = {}
        techs_by_category = {}
        stats.update({
            'cms_count': 0,
            'total_cves': 0,
            'total_sensitive_files': 0,
        })
        for domain_id_batch in _chunks(list(domain_ids)):
            placeholders = ','.join('?' for _ in domain_id_batch)
            cursor.execute(
                f"""
                SELECT c.severity, COUNT(*) AS count
                FROM cves c
                JOIN technologies t ON c.technology_id = t.id
                WHERE t.domain_id IN ({placeholders})
                GROUP BY c.severity
                """,
                domain_id_batch,
            )
            for row in cursor.fetchall():
                cves_by_severity[row['severity']] = (
                    cves_by_severity.get(row['severity'], 0) + row['count']
                )
                stats['total_cves'] += row['count']

            cursor.execute(
                f"""
                SELECT category, COUNT(*) AS count
                FROM technologies
                WHERE domain_id IN ({placeholders})
                GROUP BY category
                """,
                domain_id_batch,
            )
            for row in cursor.fetchall():
                techs_by_category[row['category']] = (
                    techs_by_category.get(row['category'], 0) + row['count']
                )

            cursor.execute(
                f"""
                SELECT COUNT(*) AS count FROM technologies
                WHERE category = 'cms' AND domain_id IN ({placeholders})
                """,
                domain_id_batch,
            )
            stats['cms_count'] += cursor.fetchone()['count']

            cursor.execute(
                f"""
                SELECT COUNT(*) AS count FROM sensitive_files
                WHERE domain_id IN ({placeholders})
                """,
                domain_id_batch,
            )
            stats['total_sensitive_files'] += cursor.fetchone()['count']

        stats['cves_critical'] = cves_by_severity.get('CRITICAL', 0)
        stats['cves_high'] = cves_by_severity.get('HIGH', 0)
        stats['cves_medium'] = cves_by_severity.get('MEDIUM', 0)
        stats['cves_low'] = cves_by_severity.get('LOW', 0)
        stats['total_technologies'] = sum(techs_by_category.values())
    except Exception as e:
        print(f"Dashboard stats error: {e}")
        _reset_finding_stats(stats)
    finally:
        if conn:
            conn.close()

    return stats
