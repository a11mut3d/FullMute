import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from contextlib import contextmanager
import sqlite3
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class DBQueries:
    def __init__(self, db_path: str):
        self.db_path = db_path

    @contextmanager
    def _get_cursor(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def add_domain(self, domain_data: dict):
        try:
            with self._get_cursor() as cursor:
                cursor.execute("PRAGMA table_info(domains)")
                columns = [column[1] for column in cursor.fetchall()]

                if 'final_url' in columns:
                    cursor.execute('''
                        INSERT OR REPLACE INTO domains
                        (domain, scanned_at, has_camera, is_alive, response_time, http_status, final_url, technologies, sensitive_files)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        domain_data.get('domain'),
                        domain_data.get('scanned_at', datetime.now()),
                        domain_data.get('has_camera', False),
                        domain_data.get('is_alive', True),
                        domain_data.get('response_time'),
                        domain_data.get('http_status'),
                        domain_data.get('final_url'),
                        json.dumps(domain_data.get('technologies', [])),
                        json.dumps(domain_data.get('sensitive_files', []))
                    ))
                else:
                    cursor.execute('''
                        INSERT OR REPLACE INTO domains
                        (domain, scanned_at, has_camera, is_alive, response_time, http_status, technologies, sensitive_files)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        domain_data.get('domain'),
                        domain_data.get('scanned_at', datetime.now()),
                        domain_data.get('has_camera', False),
                        domain_data.get('is_alive', True),
                        domain_data.get('response_time'),
                        domain_data.get('http_status'),
                        json.dumps(domain_data.get('technologies', [])),
                        json.dumps(domain_data.get('sensitive_files', []))
                    ))
        except Exception as e:
            logger.error(f"Failed to add domain {domain_data.get('domain')}: {e}")

    def add_technology(self, technology_data: dict):
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    INSERT OR IGNORE INTO technologies
                    (domain_id, category, name, version, detection_method, confidence, first_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    technology_data.get('domain_id'),
                    technology_data.get('category'),
                    technology_data.get('name'),
                    technology_data.get('version'),
                    technology_data.get('detection_method', 'signature'),
                    technology_data.get('confidence', 100),
                    technology_data.get('first_seen', datetime.now())
                ))


                cursor.execute('SELECT id FROM technologies WHERE domain_id=? AND name=? AND version=?',
                              (technology_data.get('domain_id'), technology_data.get('name'), technology_data.get('version')))
                result = cursor.fetchone()
                return result[0] if result else None
        except Exception as e:
            logger.error(f"Failed to add technology: {e}")
            return None

    def add_cve(self, cve_data: dict):
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    INSERT OR IGNORE INTO cves
                    (technology_id, cve_id, description, severity, cvss_score, cvss_version,
                     published_date, last_modified, vector_string, references_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve_data.get('technology_id'),
                    cve_data.get('cve_id'),
                    cve_data.get('description'),
                    cve_data.get('severity'),
                    cve_data.get('cvss_score'),
                    cve_data.get('cvss_version'),
                    cve_data.get('published_date'),
                    cve_data.get('last_modified'),
                    cve_data.get('vector_string'),
                    json.dumps(cve_data.get('references', []))
                ))
        except Exception as e:
            logger.error(f"Failed to add CVE: {e}")

    def add_sensitive_file(self, file_data: dict):
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    INSERT OR IGNORE INTO sensitive_files
                    (domain_id, file_path, file_type, verification_result, content_sample, found_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    file_data.get('domain_id'),
                    file_data.get('file_path'),
                    file_data.get('file_type'),
                    file_data.get('verification_result'),
                    file_data.get('content_sample'),
                    file_data.get('found_at', datetime.now())
                ))
        except Exception as e:
            logger.error(f"Failed to add sensitive file: {e}")

    def add_default_credential(self, cred_data: dict):
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    INSERT INTO default_credentials
                    (domain_id, login_url, username, password, description, detection_reason)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    cred_data.get('domain_id'),
                    cred_data.get('login_url'),
                    cred_data.get('username'),
                    cred_data.get('password'),
                    cred_data.get('description'),
                    cred_data.get('detection_reason')
                ))
        except Exception as e:
            logger.error(f"Failed to add default credential: {e}")

    def get_default_credentials_for_domain(self, domain: str) -> List[Dict[str, Any]]:
        try:
            with self._get_cursor() as cursor:
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='default_credentials'")
                if not cursor.fetchone():
                    return []

                cursor.execute('''
                    SELECT dc.* FROM default_credentials dc
                    JOIN domains d ON dc.domain_id = d.id
                    WHERE d.domain = ?
                    ORDER BY dc.found_at DESC
                ''', (domain,))

                return [dict(row) for row in cursor.fetchall()]
        except sqlite3.OperationalError as e:
            logger.debug(f"Table default_credentials not found: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to get default credentials for {domain}: {e}")
            return []

    def get_domain_id(self, domain: str) -> int:
        try:
            with self._get_cursor() as cursor:
                cursor.execute('SELECT id FROM domains WHERE domain = ?', (domain,))
                result = cursor.fetchone()
                return result[0] if result else None
        except Exception as e:
            logger.error(f"Failed to get domain ID for {domain}: {e}")
            return None

    def get_technology_id(self, domain_id: int, name: str, version: str) -> int:
        try:
            with self._get_cursor() as cursor:
                cursor.execute('SELECT id FROM technologies WHERE domain_id=? AND name=? AND version=?',
                              (domain_id, name, version))
                result = cursor.fetchone()
                return result[0] if result else None
        except Exception as e:
            logger.error(f"Failed to get technology ID for {name} {version}: {e}")
            return None

    def add_plugin(self, plugin_data: dict):
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    INSERT OR IGNORE INTO plugins
                    (domain_id, cms_type, plugin_name, version, status, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    plugin_data.get('domain_id'),
                    plugin_data.get('cms_type'),
                    plugin_data.get('plugin_name'),
                    plugin_data.get('version'),
                    plugin_data.get('status', 'active'),
                    plugin_data.get('first_seen'),
                    plugin_data.get('last_seen', plugin_data.get('first_seen'))
                ))


                cursor.execute('SELECT id FROM plugins WHERE domain_id=? AND plugin_name=? AND version=?',
                              (plugin_data.get('domain_id'), plugin_data.get('plugin_name'), plugin_data.get('version')))
                result = cursor.fetchone()
                return result[0] if result else None
        except Exception as e:
            logger.error(f"Failed to add plugin: {e}")
            return None

    def add_plugin_cve(self, plugin_cve_data: dict):
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    INSERT OR IGNORE INTO plugin_cves
                    (plugin_id, cve_id, description, severity, cvss_score, cvss_version,
                     published_date, last_modified, vector_string, references_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    plugin_cve_data.get('plugin_id'),
                    plugin_cve_data.get('cve_id'),
                    plugin_cve_data.get('description'),
                    plugin_cve_data.get('severity'),
                    plugin_cve_data.get('cvss_score'),
                    plugin_cve_data.get('cvss_version'),
                    plugin_cve_data.get('published_date'),
                    plugin_cve_data.get('last_modified'),
                    plugin_cve_data.get('vector_string'),
                    plugin_cve_data.get('references_json')
                ))
        except Exception as e:
            logger.error(f"Failed to add plugin CVE: {e}")

    def get_cves_for_technology(self, technology_id: int) -> list:
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    SELECT cve_id, description, severity, cvss_score, cvss_version,
                           published_date, last_modified, vector_string, references_json
                    FROM cves WHERE technology_id=?
                ''', (technology_id,))
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to get CVEs for technology {technology_id}: {e}")
            return []

    def get_plugins_for_domain(self, domain_id: int) -> list:
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    SELECT cms_type, plugin_name, version, status, first_seen, last_seen
                    FROM plugins WHERE domain_id=?
                ''', (domain_id,))
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to get plugins for domain {domain_id}: {e}")
            return []

    def get_cves_for_plugin(self, plugin_id: int) -> list:
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    SELECT cve_id, description, severity, cvss_score, cvss_version,
                           published_date, last_modified, vector_string, references_json
                    FROM plugin_cves WHERE plugin_id=?
                ''', (plugin_id,))
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to get CVEs for plugin {plugin_id}: {e}")
            return []

    def search_domains(self, where_clause: str = None, params: tuple = ()):
        ALLOWED_FIELDS = {
            'domain', 'has_camera', 'is_alive', 'http_status',
            'scanned_at', 'response_time', 'final_url'
        }

        ALLOWED_OPERATORS = {'=', 'LIKE', '>', '<', '>=', '<=', '!=', 'IN'}

        try:
            with self._get_cursor() as cursor:
                if not where_clause:
                    cursor.execute('SELECT * FROM domains')
                    return cursor.fetchall()
                import re

                conditions = re.split(r'\s+AND\s+', where_clause, flags=re.IGNORECASE)

                validated_conditions = []
                for condition in conditions:
                    condition = condition.strip()
                    match = re.match(r'^(\w+)\s*(=|LIKE|>|<|>=|<=|!=|IN)\s*\?$', condition, re.IGNORECASE)
                    if not match:
                        logger.error(f"Invalid WHERE clause format: {condition}")
                        raise ValueError(f"Invalid WHERE clause: {condition}")

                    field = match.group(1).lower()
                    operator = match.group(2).upper()

                    if field not in ALLOWED_FIELDS:
                        logger.error(f"Attempted SQL injection via field: {field}")
                        raise ValueError(f"Field '{field}' not allowed in query")

                    if operator not in ALLOWED_OPERATORS:
                        logger.error(f"Attempted SQL injection via operator: {operator}")
                        raise ValueError(f"Operator '{operator}' not allowed in query")

                    validated_conditions.append(f"{field} {operator} ?")

                validated_where = ' AND '.join(validated_conditions)
                sql = f'SELECT * FROM domains WHERE {validated_where}'

                logger.debug(f"Executing safe query: {sql} with params: {params}")
                cursor.execute(sql, params)
                return cursor.fetchall()

        except (ValueError, sqlite3.Error) as e:
            logger.error(f"Database query error: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to search domains: {e}")
            raise

    def fetch_all_domains(self):
        return self.search_domains()

    def add_port_scan(self, scan_data: dict) -> Optional[int]:
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    INSERT INTO port_scans
                    (domain_id, total_ports_scanned, open_ports_count, scan_duration)
                    VALUES (?, ?, ?, ?)
                ''', (
                    scan_data.get('domain_id'),
                    scan_data.get('total_ports_scanned', 0),
                    scan_data.get('open_ports_count', 0),
                    scan_data.get('scan_duration', 0.0)
                ))
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to add port scan: {e}")
            return None

    def add_open_port(self, port_data: dict) -> Optional[int]:
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    INSERT INTO open_ports
                    (port_scan_id, port, protocol, state, service, version,
                     banner, ssl, product, cves_count, exploits_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    port_data.get('port_scan_id'),
                    port_data.get('port'),
                    port_data.get('protocol', 'tcp'),
                    port_data.get('state', 'open'),
                    port_data.get('service', 'unknown'),
                    port_data.get('version', ''),
                    port_data.get('banner', ''),
                    port_data.get('ssl', False),
                    port_data.get('product', ''),
                    port_data.get('cves_count', 0),
                    port_data.get('exploits_count', 0)
                ))
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to add open port: {e}")
            return None

    def add_port_cve(self, cve_data: dict) -> Optional[int]:
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    INSERT INTO port_cves
                    (open_port_id, cve_id, description, severity, cvss_score,
                     cvss_version, published_date, last_modified, vector_string,
                     references_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve_data.get('open_port_id'),
                    cve_data.get('cve_id'),
                    cve_data.get('description'),
                    cve_data.get('severity'),
                    cve_data.get('cvss_score'),
                    cve_data.get('cvss_version'),
                    cve_data.get('published_date'),
                    cve_data.get('last_modified'),
                    cve_data.get('vector_string'),
                    json.dumps(cve_data.get('references', []))
                ))
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to add port CVE: {e}")
            return None

    def add_port_exploit(self, exploit_data: dict) -> Optional[int]:
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    INSERT INTO port_exploits
                    (port_cve_id, exploit_title, exploit_path, exploit_type,
                     platform, date, author)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    exploit_data.get('port_cve_id'),
                    exploit_data.get('exploit_title'),
                    exploit_data.get('exploit_path'),
                    exploit_data.get('exploit_type'),
                    exploit_data.get('platform'),
                    exploit_data.get('date'),
                    exploit_data.get('author')
                ))
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to add port exploit: {e}")
            return None

    def get_port_scans_for_domain(self, domain_id: int) -> List[Dict]:
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    SELECT * FROM port_scans WHERE domain_id = ?
                    ORDER BY scanned_at DESC
                ''', (domain_id,))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get port scans: {e}")
            return []

    def get_open_ports_for_scan(self, port_scan_id: int) -> List[Dict]:
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    SELECT * FROM open_ports WHERE port_scan_id = ?
                    ORDER BY port
                ''', (port_scan_id,))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get open ports: {e}")
            return []

    def get_cves_for_port(self, open_port_id: int) -> List[Dict]:
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    SELECT * FROM port_cves WHERE open_port_id = ?
                ''', (open_port_id,))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get port CVEs: {e}")
            return []

    def get_exploits_for_cve(self, port_cve_id: int) -> List[Dict]:
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    SELECT * FROM port_exploits WHERE port_cve_id = ?
                ''', (port_cve_id,))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get exploits: {e}")
            return []
