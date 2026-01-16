import json
from datetime import datetime
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

    def search_domains(self, query: str = None, params: tuple = ()):
        try:
            with self._get_cursor() as cursor:
                sql = 'SELECT * FROM domains'
                if query:
                    sql += f' WHERE {query}'
                cursor.execute(sql, params)
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to search domains: {e}")
            return []

    def fetch_all_domains(self):
        return self.search_domains()
