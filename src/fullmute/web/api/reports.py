from fastapi import APIRouter, Depends, HTTPException, status, Response
from typing import Optional
from datetime import datetime
import sqlite3
import json
from pathlib import Path
from io import BytesIO

from fullmute.utils.logger import setup_logger
from fullmute.web.auth import get_current_user
from fullmute.web.database import get_targets, get_target_groups, get_db_connection
from fullmute.web.config import config

router = APIRouter()


def get_scanner_db_path():
    db_path = Path(__file__).parent.parent.parent.parent.parent / config.scanner_database
    return str(db_path)


def get_domain_results(domain: str) -> dict:
    db_path = get_scanner_db_path()
    logger = setup_logger()

    logger.info(f"get_domain_results called for: {domain}")
    logger.info(f"Scanner DB path: {db_path}")

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Try exact match
        logger.info(f"Trying exact match for: {domain}")
        cursor.execute("SELECT * FROM domains WHERE domain = ?", (domain,))
        domain_row = cursor.fetchone()

        # Try clean domain if exact match fails
        if not domain_row:
            clean_domain = domain.replace('http://', '').replace('https://', '').rstrip('/')
            logger.info(f"Exact match failed, trying clean domain: {clean_domain}")
            cursor.execute("SELECT * FROM domains WHERE domain LIKE ?", (f'%{clean_domain}%',))
            domain_row = cursor.fetchone()

        # Try with www prefix
        if not domain_row:
            logger.info(f"Clean match failed, trying with www")
            cursor.execute("SELECT * FROM domains WHERE domain LIKE ?", (f'%www.{domain}%',))
            domain_row = cursor.fetchone()

        if not domain_row:
            logger.warning(f"No domain found in scanner DB for: {domain}")
            cursor.execute("SELECT domain FROM domains")
            all_domains = [row['domain'] for row in cursor.fetchall()]
            logger.info(f"All domains in scanner DB: {all_domains}")
            conn.close()
            return None

        logger.info(f"Found domain in scanner DB: {domain_row['domain']} (ID: {domain_row['id']})")
        result = dict(domain_row)

        # Get technologies
        cursor.execute("SELECT * FROM technologies WHERE domain_id = ?", (domain_row['id'],))
        result['technologies'] = [dict(row) for row in cursor.fetchall()]
        logger.info(f"Found {len(result['technologies'])} technologies")

        # Get CVEs
        cursor.execute("""
            SELECT c.* FROM cves c
            JOIN technologies t ON c.technology_id = t.id
            WHERE t.domain_id = ?
        """, (domain_row['id'],))
        result['cves'] = [dict(row) for row in cursor.fetchall()]
        logger.info(f"Found {len(result['cves'])} CVEs")

        # Get sensitive files
        cursor.execute("SELECT * FROM sensitive_files WHERE domain_id = ?", (domain_row['id'],))
        result['sensitive_files'] = [dict(row) for row in cursor.fetchall()]
        logger.info(f"Found {len(result['sensitive_files'])} sensitive files")

        # Get default credentials
        cursor.execute("""
            SELECT * FROM default_credentials WHERE domain_id = ?
        """, (domain_row['id'],))
        result['default_credentials'] = [dict(row) for row in cursor.fetchall()]
        logger.info(f"Found {len(result['default_credentials'])} default credentials")

        # Get open ports - FIXED: handle different column names
        try:
            # Check table structure
            cursor.execute("PRAGMA table_info(open_ports)")
            columns = [col[1] for col in cursor.fetchall()]
            logger.info(f"open_ports columns: {columns}")

            # Try different column names
            if 'target_id' in columns:
                cursor.execute("SELECT * FROM open_ports WHERE target_id = ?", (domain_row['id'],))
            elif 'domain_id' in columns:
                cursor.execute("SELECT * FROM open_ports WHERE domain_id = ?", (domain_row['id'],))
            elif 'domain' in columns:
                cursor.execute("SELECT * FROM open_ports WHERE domain = ?", (domain_row['domain'],))
            else:
                logger.warning(f"No suitable column in open_ports. Available: {columns}")
                open_ports = []

            open_ports = [dict(row) for row in cursor.fetchall()]
            logger.info(f"Found {len(open_ports)} open ports")
        except Exception as e:
            logger.error(f"Error getting open ports: {e}")
            open_ports = []

        # Process exploits and SSH credentials
        all_exploits = []
        ssh_creds = []

        for port in open_ports:
            # Get exploits
            if port.get('exploits'):
                exploits = port.get('exploits', [])
                if isinstance(exploits, list):
                    for exploit in exploits:
                        if isinstance(exploit, dict):
                            exploit['port'] = port.get('port')
                            exploit['service'] = port.get('service')
                            all_exploits.append(exploit)
                        elif isinstance(exploit, str):
                            all_exploits.append({
                                'description': exploit,
                                'port': port.get('port'),
                                'service': port.get('service')
                            })

            # Get SSH credentials
            if port.get('port') == 22 and port.get('default_credentials'):
                creds = port.get('default_credentials', [])
                if isinstance(creds, list):
                    for cred in creds:
                        if isinstance(cred, dict):
                            cred['port'] = 22
                            cred['service'] = 'ssh'
                            ssh_creds.append(cred)
                        elif isinstance(cred, str):
                            ssh_creds.append({
                                'credential': cred,
                                'port': 22,
                                'service': 'ssh'
                            })

        result['exploits'] = all_exploits
        result['ssh_credentials'] = ssh_creds
        result['open_ports'] = open_ports
        logger.info(f"Found {len(all_exploits)} exploits and {len(ssh_creds)} SSH credentials")

        conn.close()
        return result

    except Exception as e:
        logger.error(f"Error getting domain results: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None


@router.get("/group/{group_id}/json")
async def generate_group_report_json(
    group_id: int,
    current_user: dict = Depends(get_current_user)
):
    logger = setup_logger()
    logger.info(f"Generating JSON report for group {group_id} by user {current_user['username']} (role: {current_user['role']})")

    targets = get_targets(group_id=group_id)
    logger.info(f"Found {len(targets)} targets in group {group_id}")
    for t in targets:
        logger.info(f"  Target: {t}")

    if current_user['role'] != 'admin' and not targets:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, created_by FROM target_groups WHERE id = ?", (group_id,))
            group = cursor.fetchone()
            if not group:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Group not found"
                )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. You can only access reports for your own targets."
            )

    if not targets:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No targets found in group"
        )

    report_data = {
        "generated_at": datetime.now().isoformat(),
        "generated_by": current_user['username'],
        "group_id": group_id,
        "total_targets": len(targets),
        "domains": []
    }

    for target in targets:
        domain = target.get('domain')
        logger.info(f"Getting results for domain: {domain}")
        domain_results = get_domain_results(domain)
        if domain_results:
            logger.info(f"Found results for {domain}: {len(domain_results.get('technologies', []))} techs, {len(domain_results.get('cves', []))} cves")
            report_data['domains'].append(domain_results)
        else:
            logger.warning(f"No results for {domain}")

    report_data['summary'] = {
        "scanned": len(report_data['domains']),
        "with_vulnerabilities": sum(1 for d in report_data['domains'] if d.get('cves')),
        "with_sensitive_files": sum(1 for d in report_data['domains'] if d.get('sensitive_files')),
        "with_default_credentials": sum(1 for d in report_data['domains'] if d.get('default_credentials')),
        "total_default_credentials": sum(len(d.get('default_credentials', [])) for d in report_data['domains']),
        "with_exploits": sum(1 for d in report_data['domains'] if d.get('exploits')),
        "total_exploits": sum(len(d.get('exploits', [])) for d in report_data['domains']),
        "with_ssh_credentials": sum(1 for d in report_data['domains'] if d.get('ssh_credentials')),
        "total_ssh_credentials": sum(len(d.get('ssh_credentials', [])) for d in report_data['domains']),
    }

    return report_data


@router.get("/group/{group_id}/download")
async def download_group_report(
    group_id: int,
    format: str = "pdf",
    current_user: dict = Depends(get_current_user)
):
    from fastapi.responses import Response
    import traceback
    from fullmute.web.pdf_generator import generate_pdf_report

    logger = setup_logger()

    try:
        logger.info(f"Generating {format.upper()} report for group {group_id} by user {current_user['username']} (role: {current_user['role']})")

        targets = get_targets(group_id=group_id)
        logger.info(f"Found {len(targets)} targets in group {group_id}")
        for t in targets:
            logger.info(f"  Target: {t}")

        if current_user['role'] != 'admin' and not targets:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, created_by FROM target_groups WHERE id = ?", (group_id,))
                group = cursor.fetchone()
                if not group:
                    logger.warning(f"Group {group_id} not found")
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Group not found"
                    )
                logger.warning(f"User {current_user['username']} tried to access group {group_id} they don't own")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied. You can only access reports for your own targets."
                )

        if not targets:
            logger.warning(f"No targets in group {group_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No targets found in group"
            )

        report_data = {
            "generated_at": datetime.now().isoformat(),
            "generated_by": current_user['username'],
            "group_id": group_id,
            "total_targets": len(targets),
            "domains": []
        }

        for target in targets:
            logger.info(f"Processing target: {target}")

            domain = target.get('domain')
            if not domain:
                logger.warning(f"No domain in target: {target}")
                continue
            logger.info(f"Getting results for domain: {domain}")
            domain_results = get_domain_results(domain)
            if domain_results:
                logger.info(f"Found results for {domain}: {len(domain_results.get('technologies', []))} techs, {len(domain_results.get('cves', []))} cves")
                report_data['domains'].append(domain_results)
            else:
                logger.warning(f"No results for {domain}")

        report_data['summary'] = {
            "scanned": len(report_data['domains']),
            "with_vulnerabilities": sum(1 for d in report_data['domains'] if d.get('cves')),
            "with_sensitive_files": sum(1 for d in report_data['domains'] if d.get('sensitive_files')),
            "with_default_credentials": sum(1 for d in report_data['domains'] if d.get('default_credentials')),
            "total_default_credentials": sum(len(d.get('default_credentials', [])) for d in report_data['domains']),
            "with_exploits": sum(1 for d in report_data['domains'] if d.get('exploits')),
            "total_exploits": sum(len(d.get('exploits', [])) for d in report_data['domains']),
            "with_ssh_credentials": sum(1 for d in report_data['domains'] if d.get('ssh_credentials')),
            "total_ssh_credentials": sum(len(d.get('ssh_credentials', [])) for d in report_data['domains']),
        }

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if format.lower() == 'pdf':
            logger.info("Generating PDF report")
            pdf_bytes = generate_pdf_report(report_data)
            filename = f"fullmute_report_group{group_id}_{timestamp}.pdf"
            logger.info(f"PDF report generated successfully: {filename}")

            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f"attachment; filename={filename}"
                }
            )
        else:
            filename = f"fullmute_report_group{group_id}_{timestamp}.json"

            return Response(
                content=json.dumps(report_data, indent=2, default=str),
                media_type="application/json",
                headers={
                    "Content-Disposition": f"attachment; filename={filename}"
                }
            )
    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        logger.error(f"Error generating report: {error_trace}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error generating report: {str(e)}"
        )


@router.get("/group/{group_id}/summary")
async def get_group_summary(
    group_id: int,
    current_user: dict = Depends(get_current_user)
):
    logger = setup_logger()
    logger.info(f"Getting summary for group {group_id}")

    targets = get_targets(group_id=group_id)

    if not targets:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No targets found in group"
        )

    summary = {
        "total_targets": len(targets),
        "scanned": 0,
        "with_cameras": 0,
        "with_technologies": 0,
        "with_cves": 0,
        "with_sensitive_files": 0,
        "total_cves": 0,
        "total_sensitive_files": 0
    }

    db_path = get_scanner_db_path()

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        for target in targets:
            cursor.execute("SELECT * FROM domains WHERE domain = ?", (target['domain'],))
            domain_row = cursor.fetchone()

            if domain_row:
                summary['scanned'] += 1

                if domain_row.get('has_camera'):
                    summary['with_cameras'] += 1

                # Get technologies count
                cursor.execute("SELECT COUNT(*) FROM technologies WHERE domain_id = ?", (domain_row['id'],))
                tech_count = cursor.fetchone()[0]
                if tech_count > 0:
                    summary['with_technologies'] += 1

                # Get CVEs count
                cursor.execute("""
                    SELECT COUNT(*) FROM cves c
                    JOIN technologies t ON c.technology_id = t.id
                    WHERE t.domain_id = ?
                """, (domain_row['id'],))
                cve_count = cursor.fetchone()[0]
                if cve_count > 0:
                    summary['with_cves'] += 1
                    summary['total_cves'] += cve_count

                # Get sensitive files count
                cursor.execute("SELECT COUNT(*) FROM sensitive_files WHERE domain_id = ?", (domain_row['id'],))
                file_count = cursor.fetchone()[0]
                if file_count > 0:
                    summary['with_sensitive_files'] += 1
                    summary['total_sensitive_files'] += file_count

        conn.close()

    except Exception as e:
        logger.error(f"Error getting summary: {e}")

    return summary


@router.get("/group/{group_id}/domains")
async def get_group_domains(
    group_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Get all domains in a group"""
    targets = get_targets(group_id=group_id)

    if not targets:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No targets found in group"
        )

    domains = []
    for target in targets:
        domain_results = get_domain_results(target['domain'])
        if domain_results:
            domains.append({
                "domain": target['domain'],
                "technologies_count": len(domain_results.get('technologies', [])),
                "cves_count": len(domain_results.get('cves', [])),
                "sensitive_files_count": len(domain_results.get('sensitive_files', [])),
                "default_credentials_count": len(domain_results.get('default_credentials', [])),
                "open_ports_count": len(domain_results.get('open_ports', []))
            })

    return {
        "group_id": group_id,
        "total_domains": len(targets),
        "scanned_domains": len(domains),
        "domains": domains
    }
